"""Regression tests for the issues found in the end-to-end QA pass of the Domains sub-pages."""
import csv
import io
import json
import random
from datetime import datetime, time, timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from core.models import AuditEvent, Membership, Site

from . import analytics, security
from .models import Domain, DomainCheck, DomainSecurityScan
from .test_security import facts


def _csv(resp):
    return list(csv.reader(io.StringIO(resp.content.decode())))


class SitePermissionTests(TestCase):
    """An operator of one site who only views another must not change the other site's domains."""

    def setUp(self):
        mumbai = Site.objects.create(name="Mumbai", code="mumbai")
        dr = Site.objects.create(name="DR Site", code="dr")
        self.user = User.objects.create_user("site-op", password="x" * 14)
        Membership.objects.create(user=self.user, site=mumbai, role="operator")
        Membership.objects.create(user=self.user, site=dr, role="viewer")
        self.mine = Domain.objects.create(tenant_key="default", hostname="mine.example.com", site_key="Mumbai")
        self.theirs = Domain.objects.create(tenant_key="default", hostname="theirs.example.com", site_key="DR Site")
        self.shared = Domain.objects.create(tenant_key="default", hostname="shared.example.com", site_key="All Sites")
        self.foreign = Domain.objects.create(tenant_key="other", hostname="foreign.example.com", site_key="Mumbai")
        self.client.force_login(self.user)

    @mock.patch("domainmonitor.security.run_scans")
    def test_scan_now_needs_operate_on_the_domains_site(self, run):
        run.side_effect = lambda ds: [security.save_scan(d, facts(hostname=d.hostname)) for d in ds]
        r = self.client.post(reverse("domains:security_scan", args=[self.theirs.pk]))
        self.assertEqual(r.status_code, 302)
        run.assert_not_called()
        self.assertFalse(DomainSecurityScan.objects.exists())
        self.assertFalse(AuditEvent.objects.filter(action="run", object_id=str(self.theirs.pk)).exists())
        for d in (self.mine, self.shared):
            self.client.post(reverse("domains:security_scan", args=[d.pk]))
            self.assertTrue(AuditEvent.objects.filter(action="run", object_id=str(d.pk), actor=self.user).exists())
        self.assertEqual(run.call_count, 2)

    @mock.patch("domainmonitor.security.run_scans", return_value=[])
    def test_scan_all_only_covers_operable_domains(self, run):
        self.client.post(reverse("domains:security_scan_all"))
        scanned = {d.hostname for d in run.call_args[0][0]}
        self.assertEqual(scanned, {"mine.example.com", "shared.example.com"})

    @mock.patch("probes.runner.run_domain_checks", return_value=[])
    def test_run_all_only_covers_operable_domains(self, run):
        r = self.client.post(reverse("domains:run_all"), HTTP_X_CSRFTOKEN="x", HTTP_ACCEPT="application/json")
        self.assertEqual(r.json()["checked"], 2)
        self.assertEqual({d.hostname for d in run.call_args[0][0]}, {"mine.example.com", "shared.example.com"})

    def test_toggle_and_quick_actions_are_refused_on_view_only_site(self):
        self.client.post(reverse("domains:toggle", args=[self.theirs.pk]))
        self.theirs.refresh_from_db()
        self.assertTrue(self.theirs.is_active)
        r = self.client.post(reverse("domains:action", args=[self.theirs.pk, "dns"]), HTTP_X_CSRFTOKEN="x")
        self.assertEqual(r.status_code, 403)
        self.client.post(reverse("domains:toggle", args=[self.mine.pk]))
        self.mine.refresh_from_db()
        self.assertFalse(self.mine.is_active)
        self.assertEqual(AuditEvent.objects.filter(actor=self.user).count(), 1)

    @mock.patch("probes.runner.run_domain_checks")
    def test_add_and_edit_need_operate_on_the_target_site(self, _run):
        form = {"domain_type": "API", "check_interval_seconds": 300}
        r = self.client.post(reverse("domains:list"), {**form, "hostname": "new.example.com", "site_key": "DR Site"})
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "You do not have operator rights on this site.")
        self.assertFalse(Domain.objects.filter(hostname="new.example.com").exists())
        # moving one of my domains to a site I only view
        self.client.post(reverse("domains:list"), {**form, "pk": self.mine.pk, "hostname": self.mine.hostname, "site_key": "DR Site"})
        self.mine.refresh_from_db()
        self.assertEqual(self.mine.site_key, "Mumbai")
        # editing a domain of a site I only view
        self.client.post(reverse("domains:list"), {**form, "pk": self.theirs.pk, "hostname": self.theirs.hostname,
                                                   "site_key": "DR Site", "description": "changed"})
        self.theirs.refresh_from_db()
        self.assertEqual(self.theirs.description, "")
        # allowed: add on my own site
        r = self.client.post(reverse("domains:list"), {**form, "hostname": "ok.example.com", "site_key": "Mumbai"})
        self.assertEqual(r.status_code, 302)
        self.assertTrue(AuditEvent.objects.filter(action="create", object_repr="ok.example.com").exists())

    def test_edit_with_unknown_or_foreign_pk_does_not_create_a_domain(self):
        before = Domain.objects.count()
        for pk in (self.foreign.pk, 999999, "abc"):
            r = self.client.post(reverse("domains:list"), {"pk": pk, "hostname": f"x{before}.example.com", "domain_type": "API",
                                                           "site_key": "Mumbai", "check_interval_seconds": 300})
            self.assertEqual(r.status_code, 404, pk)
        self.assertEqual(Domain.objects.count(), before)

    def test_row_actions_follow_the_row_site(self):
        security.save_scan(self.mine, facts(hostname=self.mine.hostname))
        r = self.client.get(reverse("domains:security"))
        self.assertContains(r, reverse("domains:security_scan", args=[self.mine.pk]))
        self.assertContains(r, reverse("domains:security_scan", args=[self.shared.pk]))
        self.assertNotContains(r, reverse("domains:security_scan", args=[self.theirs.pk]))
        r = self.client.get(reverse("domains:security") + f"?selected={self.theirs.pk}")
        self.assertContains(r, 'id="scan-detail"')
        self.assertNotContains(r, reverse("domains:security_scan", args=[self.theirs.pk]))
        r = self.client.get(reverse("domains:list") + f"?selected={self.theirs.pk}")
        self.assertNotContains(r, f"?edit={self.theirs.pk}")
        self.assertNotContains(r, reverse("domains:toggle", args=[self.theirs.pk]))
        self.assertContains(r, reverse("domains:toggle", args=[self.mine.pk]))
        self.assertNotContains(r, "Quick Actions")
        r = self.client.get(reverse("domains:list") + f"?edit={self.theirs.pk}")
        self.assertNotContains(r, 'id="domain-form"')
        r = self.client.get(reverse("domains:overview"))
        self.assertContains(r, reverse("domains:action", args=[self.mine.pk, "uptime"]))
        self.assertNotContains(r, reverse("domains:action", args=[self.theirs.pk, "uptime"]))


class CsvInjectionTests(TestCase):
    """Header values come from remote servers and names from operators: exported cells must not run as formulas."""

    def setUp(self):
        self.admin = User.objects.create_superuser("admin", "a@example.com", "x" * 14)
        self.d = Domain.objects.create(tenant_key="default", hostname="evil.example.com", site_key="=Site",
                                       group="+cmd|' /C calc'!A0", description="@SUM(1+1)")
        self.client.force_login(self.admin)

    def test_security_csv_neutralises_remote_header_formulas(self):
        headers = {"server": '=HYPERLINK("http://attacker.example/","click")', "content-security-policy": "-1+1"}
        security.save_scan(self.d, facts(hostname=self.d.hostname, headers=headers))
        rows = _csv(self.client.get(reverse("domains:security") + "?format=csv"))
        row = dict(zip(rows[0], rows[1]))
        self.assertEqual(row["server"], '\'=HYPERLINK("http://attacker.example/","click")')
        self.assertEqual(row["csp"], "'-1+1")
        self.assertEqual(row["site"], "'=Site")

    def test_report_and_list_exports_neutralise_formulas(self):
        rows = _csv(self.client.get(reverse("domains:export_reports") + "?format=csv"))
        row = dict(zip(rows[0], rows[1]))
        self.assertEqual(row["site"], "'=Site")
        self.assertEqual(row["group"], "'+cmd|' /C calc'!A0")
        rows = _csv(self.client.get(reverse("domains:export")))
        row = dict(zip(rows[0], rows[1]))
        self.assertEqual(row["description"], "'@SUM(1+1)")
        for name in ("domains:uptime", "domains:performance"):
            rows = _csv(self.client.get(reverse(name) + "?format=csv"))
            self.assertEqual(rows[1][1], "'=Site", name)

    def test_numbers_are_not_altered(self):
        now = timezone.now()
        for h, ms in ((30, 400), (2, 100)):
            DomainCheck.objects.create(domain=self.d, checked_at=now - timedelta(hours=h), up=True, response_ms=ms,
                                       dns_status="Resolved", ssl_status="Valid")
        rows = _csv(self.client.get(reverse("domains:performance") + "?format=csv"))
        row = dict(zip(rows[0], rows[1]))
        self.assertEqual(row["p95_change_pct"], "-75.0")


class ApiAuditTests(TestCase):
    def test_api_mutations_write_audit_rows(self):
        staff = User.objects.create_user("staff", password="x" * 14, is_staff=True)
        c = Client()
        c.force_login(staff)
        r = c.post("/configuration/domains/api/", json.dumps({"tenant": "default", "site": "Mumbai", "hostname": "api.example.com"}),
                   content_type="application/json")
        self.assertEqual(r.status_code, 201)
        pk = r.json()["id"]
        r = c.patch(f"/configuration/domains/api/{pk}/?tenant=default", json.dumps({"description": "x"}), content_type="application/json")
        self.assertEqual(r.json(), {"status": "updated"})
        r = c.delete(f"/configuration/domains/api/{pk}/?tenant=default")
        self.assertEqual(r.json(), {"status": "deactivated"})
        actions = list(AuditEvent.objects.filter(object_id=str(pk)).order_by("pk").values_list("action", flat=True))
        self.assertEqual(actions, ["create", "update", "update"])


class SchedulerOrderTests(TestCase):
    def test_never_scanned_domains_come_first(self):
        old = Domain.objects.create(tenant_key="default", hostname="a-old.example.com", site_key="x")
        new = Domain.objects.create(tenant_key="default", hostname="z-new.example.com", site_key="x")
        DomainSecurityScan.objects.create(domain=old, scanned_at=timezone.now() - timedelta(days=3))
        self.assertEqual(security.due_domains(limit=1), [new])


def reference_periods(domain_ids, since, now):
    """Straightforward row-by-row version of downtime_periods(), used to check the SQL implementation."""
    out, current = [], {}
    rows = (DomainCheck.objects.filter(domain_id__in=list(domain_ids), checked_at__gte=since)
            .order_by("domain_id", "checked_at", "id").values_list("domain_id", "checked_at", "up", "message"))
    for pk, at, up, message in rows:
        p = current.get(pk)
        if not up:
            if p is None:
                current[pk] = {"domain_id": pk, "start": at, "end": None, "failed": 1, "message": message, "last_failed": at}
            else:
                p["failed"] += 1
                p["last_failed"] = at
        elif p is not None:
            p["end"] = at
            out.append(current.pop(pk))
    out.extend(current.values())
    for p in out:
        p["ongoing"] = p["end"] is None
        p["duration"] = (p["end"] or now) - p["start"]
    out.sort(key=lambda p: p["start"], reverse=True)
    return out


class AnalyticsEquivalenceTests(TestCase):
    """daily_availability / downtime_periods now count in SQL; results must match a row-by-row computation."""

    def test_downtime_periods_match_reference(self):
        rnd = random.Random(7)
        now = timezone.now().replace(microsecond=0)
        domains = [Domain.objects.create(tenant_key="default", hostname=f"d{i}.example.com", site_key="x") for i in range(4)]
        for d in domains:
            up = rnd.random() < 0.5
            for k in range(300):
                if rnd.random() < 0.08:
                    up = not up
                DomainCheck.objects.create(domain=d, checked_at=now - timedelta(minutes=17 * k), up=up, dns_status="Resolved",
                                           ssl_status="Valid", message="" if up else f"fail {k}")
        ids = [d.pk for d in domains]
        for since in (now - timedelta(days=30), now - timedelta(hours=20), now - timedelta(minutes=1)):
            got = analytics.downtime_periods(ids, since, now)
            want = reference_periods(ids, since, now)
            key = lambda p: (p["domain_id"], p["start"], p["end"], p["failed"], p["last_failed"], p["ongoing"],  # noqa: E731
                             p["duration"], p["message"])
            self.assertEqual([key(p) for p in got], [key(p) for p in want])
        self.assertEqual(analytics.downtime_periods([], now - timedelta(days=1), now), [])

    def test_daily_availability_uses_local_calendar_days(self):
        d = Domain.objects.create(tenant_key="default", hostname="tz.example.com", site_key="x")
        today = timezone.localdate()
        midnight = timezone.make_aware(datetime.combine(today, time.min))
        # 23:59 local yesterday (down) and 00:01 local today (up): must land on different days
        DomainCheck.objects.create(domain=d, checked_at=midnight - timedelta(minutes=1), up=False, dns_status="Failed", ssl_status="Unknown")
        DomainCheck.objects.create(domain=d, checked_at=midnight + timedelta(minutes=1), up=True, dns_status="Resolved", ssl_status="Valid")
        # outside the 3-day window
        DomainCheck.objects.create(domain=d, checked_at=midnight - timedelta(days=3, minutes=1), up=False, dns_status="Failed",
                                   ssl_status="Unknown")
        dates, overall, per = analytics.daily_availability([d.pk], 3)
        self.assertEqual(dates, [today - timedelta(days=2), today - timedelta(days=1), today])
        self.assertEqual(overall, [None, 0.0, 100.0])
        self.assertEqual([c["n"] for c in per[d.pk]], [0, 1, 1])
