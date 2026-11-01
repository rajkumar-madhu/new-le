"""Uptime / Performance / Security / Export Reports pages, permissions, mutations and the seed command."""
import csv
import io
import json
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from core.models import AuditEvent, Membership, Site

from . import security
from .models import Domain, DomainCheck, DomainSecurityScan
from .test_security import GOOD_HEADERS, facts


class InsightBase(TestCase):
    def setUp(self):
        self.viewer = User.objects.create_user("viewer", password="x" * 14)
        self.operator = User.objects.create_user("operator", password="x" * 14, is_staff=True)
        self.admin = User.objects.create_superuser("admin", "a@example.com", "x" * 14)
        now = timezone.now()
        self.a = Domain.objects.create(tenant_key="default", hostname="a.example.com", site_key="Mumbai", status="up",
                                       dns_status="Resolved", ssl_status="Valid", domain_type="API", ip_address="203.0.113.1",
                                       ssl_expires_at=now + timedelta(days=60), last_checked_at=now)
        self.b = Domain.objects.create(tenant_key="default", hostname="b.example.com", site_key="DR Site", status="down",
                                       dns_status="Resolved", ssl_status="Expiring")
        self.off = Domain.objects.create(tenant_key="default", hostname="off.example.com", site_key="Mumbai", is_active=False)
        self.other = Domain.objects.create(tenant_key="other", hostname="tenant.example.com", site_key="Mumbai")
        for h in range(1, 13):     # a: always up, 100..210 ms in the last 12 h; 400 ms in the 12 h before yesterday
            DomainCheck.objects.create(domain=self.a, checked_at=now - timedelta(hours=h), up=True, response_ms=90 + 10 * h,
                                       dns_status="Resolved", ssl_status="Valid")
            DomainCheck.objects.create(domain=self.a, checked_at=now - timedelta(hours=24 + h), up=True, response_ms=400,
                                       dns_status="Resolved", ssl_status="Valid")
        for h, up in ((5, True), (4, False), (3, False), (2, True), (1, False)):
            DomainCheck.objects.create(domain=self.b, checked_at=now - timedelta(hours=h), up=up, response_ms=500 if up else None,
                                       dns_status="Resolved", ssl_status="Expiring", message="" if up else "HTTP 503")


class PageRenderTests(InsightBase):
    urls = ("domains:uptime", "domains:performance", "domains:security", "domains:export_reports")

    def test_pages_render_for_every_role(self):
        security.save_scan(self.a, facts(hostname=self.a.hostname))
        for user in (self.viewer, self.operator, self.admin):
            self.client.force_login(user)
            for name in self.urls:
                r = self.client.get(reverse(name))
                self.assertEqual(r.status_code, 200, (user, name))
                self.assertContains(r, 'class="on">' if name != "domains:export_reports" else "Domain Status Report")
                self.assertNotContains(r, "tenant.example.com")

    def test_paths_and_query_variants(self):
        self.assertEqual(reverse("domains:uptime"), "/domains/uptime/")
        self.assertEqual(reverse("domains:performance"), "/domains/performance/")
        self.assertEqual(reverse("domains:security"), "/domains/security/")
        self.assertEqual(reverse("domains:export_reports"), "/domains/export/")
        self.client.force_login(self.viewer)
        for url in ("/domains/uptime/?days=7&sort=uptime&per=5&site=Mumbai", "/domains/uptime/?days=bogus&sort=downtime&per=x",
                    "/domains/performance/?window=720&sort=-change", "/domains/performance/?window=6&sort=hostname&type=API",
                    "/domains/performance/?window=bad&sort=-max", "/domains/security/?grade=A&sort=-grade",
                    "/domains/security/?grade=none", "/domains/security/?grade=error&sort=grade",
                    f"/domains/security/?selected={self.b.pk}", "/domains/export/?active=all&ssl=Valid",
                    "/domains/export/?site=DR%20Site&type=Production"):
            self.assertEqual(self.client.get(url).status_code, 200, url)
        # another tenant's (or an unknown) domain is never shown; the stale/forged ?selected= is ignored
        for pk in (self.other.pk, 999999):
            r = self.client.get(f"/domains/security/?selected={pk}")
            self.assertEqual(r.status_code, 200)
            self.assertNotContains(r, "tenant.example.com")
            self.assertNotContains(r, 'id="scan-detail"')

    def test_empty_database(self):
        Domain.objects.all().delete()
        self.client.force_login(self.viewer)
        for name in self.urls:
            self.assertEqual(self.client.get(reverse(name)).status_code, 200, name)

    def test_tabs_link_to_new_pages(self):
        self.client.force_login(self.viewer)
        r = self.client.get(reverse("domains:overview"))
        for name in self.urls:
            self.assertContains(r, f'href="{reverse(name)}"')


class UptimeTests(InsightBase):
    def test_uptime_numbers_and_downtime_periods(self):
        self.client.force_login(self.viewer)
        r = self.client.get(reverse("domains:uptime") + "?days=7")
        rows = {d.hostname: d for d in r.context["page"]}
        self.assertEqual(set(rows), {"a.example.com", "b.example.com"})   # inactive and other tenant excluded
        self.assertEqual(rows["a.example.com"].u24, 100.0)
        self.assertEqual(rows["b.example.com"].u24, 40.0)
        self.assertEqual(rows["b.example.com"].down_count, 2)
        periods = r.context["periods"]
        self.assertEqual(len(periods), 2)
        self.assertTrue(periods[0]["ongoing"])
        self.assertEqual(periods[1]["duration"], timedelta(hours=2))
        self.assertEqual(r.context["k"]["incidents"], 2)
        self.assertEqual(r.context["k"]["ongoing"], 1)
        self.assertEqual(len(r.context["chart"]["labels"]), 7)
        self.assertContains(r, "Ongoing")

    def test_uptime_csv_exports(self):
        self.client.force_login(self.viewer)
        r = self.client.get(reverse("domains:uptime") + "?format=csv")
        rows = list(csv.reader(io.StringIO(r.content.decode())))
        self.assertEqual(rows[0][:5], ["hostname", "site", "type", "status", "uptime_24h"])
        self.assertIn(["b.example.com", "DR Site", "Production", "down", "40.00"], [x[:5] for x in rows[1:]])
        r = self.client.get(reverse("domains:uptime") + "?format=csv&what=downtime")
        rows = list(csv.reader(io.StringIO(r.content.decode())))
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[1][4], "yes")


class PerformanceTests(InsightBase):
    def test_percentiles_and_comparison(self):
        self.client.force_login(self.viewer)
        r = self.client.get(reverse("domains:performance") + "?window=24")
        rows = {d.hostname: d for d in r.context["page"]}
        a = rows["a.example.com"]
        self.assertEqual(a.cur["n"], 12)
        self.assertEqual(a.cur["max"], 210)
        self.assertEqual(a.cur["p50"], 155)
        self.assertEqual(a.prev["p95"], 400)
        self.assertLess(a.change, -20)
        self.assertEqual(a.trend[0], "Improved")
        self.assertEqual(rows["b.example.com"].trend[0], "New")      # no previous data
        self.assertEqual([d.hostname for d in r.context["slowest"]][0], "b.example.com")
        self.assertEqual(r.context["k"]["improved"], 1)
        names = [s["name"] for s in r.context["chart"]["series"]]
        self.assertEqual(names, ["p95", "p50", "p95 (previous window)"])
        self.assertEqual(len(r.context["chart"]["labels"]), 24)

    def test_performance_csv(self):
        self.client.force_login(self.viewer)
        r = self.client.get(reverse("domains:performance") + "?format=csv&site=Mumbai")
        rows = list(csv.reader(io.StringIO(r.content.decode())))
        self.assertEqual([x[0] for x in rows[1:]], ["a.example.com"])
        self.assertEqual(rows[1][3], "12")


class SecurityPageTests(InsightBase):
    def test_grades_findings_and_recommendations(self):
        security.save_scan(self.a, facts(hostname=self.a.hostname))
        security.save_scan(self.b, facts(hostname=self.b.hostname, headers={"server": "Apache/2.4.1"}))
        self.client.force_login(self.viewer)
        r = self.client.get(reverse("domains:security") + f"?selected={self.b.pk}")
        self.assertEqual(r.context["counts"]["A"], 1)
        self.assertEqual(r.context["counts"]["F"], 1)
        self.assertEqual(r.context["k"]["hsts_missing"], 1)
        recs = {x["key"]: x for x in r.context["recommendations"]}
        self.assertIn("hsts", recs)
        self.assertEqual([d.hostname for d in recs["hsts"]["domains"]], ["b.example.com"])
        self.assertEqual(r.context["recommendations"][0]["severity"], "high")
        self.assertEqual(len(r.context["failed_findings"]), 7)
        self.assertContains(r, "Strict-Transport-Security")
        self.assertContains(r, "<code>")
        self.assertNotContains(r, reverse("domains:security_scan", args=[self.a.pk]))   # viewer: no scan buttons
        r = self.client.get(reverse("domains:security") + "?grade=A")
        self.assertEqual([d.hostname for d in r.context["page"]], ["a.example.com"])

    def test_security_csv(self):
        security.save_scan(self.a, facts(hostname=self.a.hostname))
        self.client.force_login(self.viewer)
        rows = list(csv.reader(io.StringIO(self.client.get(reverse("domains:security") + "?format=csv").content.decode())))
        by_host = {x[0]: x for x in rows[1:]}
        self.assertEqual(by_host["a.example.com"][2:4], ["A", "100"])
        self.assertEqual(by_host["b.example.com"][-1], "not scanned")


@mock.patch.object(security, "scan_host", side_effect=lambda host: facts(hostname=host))
class SecurityMutationTests(InsightBase):
    def test_viewer_cannot_scan(self, scan):
        self.client.force_login(self.viewer)
        r = self.client.post(reverse("domains:security_scan", args=[self.a.pk]))
        self.assertEqual(r.status_code, 302)
        r = self.client.post(reverse("domains:security_scan_all"), HTTP_X_CSRFTOKEN="x")
        self.assertEqual(r.status_code, 403)
        scan.assert_not_called()
        self.assertFalse(DomainSecurityScan.objects.exists())

    def test_operator_scan_now(self, scan):
        self.client.force_login(self.operator)
        r = self.client.post(reverse("domains:security_scan", args=[self.a.pk]), follow=True)
        self.assertRedirects(r, reverse("domains:security") + f"?selected={self.a.pk}#scan-detail")
        self.assertContains(r, "Scanned a.example.com: grade A (100/100).")
        scan.assert_called_once_with("a.example.com")
        self.assertEqual(DomainSecurityScan.objects.get().grade, "A")
        ev = AuditEvent.objects.get(action="run", object_id=str(self.a.pk))
        self.assertEqual((ev.actor, ev.details["check"], ev.details["grade"]), (self.operator, "security_scan", "A"))

    def test_scan_failure_message(self, scan):
        scan.side_effect = lambda host: security.ScanData(hostname=host, error="Connection refused on port 443")
        self.client.force_login(self.operator)
        r = self.client.post(reverse("domains:security_scan", args=[self.a.pk]), follow=True)
        self.assertContains(r, "Could not scan a.example.com: Connection refused on port 443")
        self.assertEqual(DomainSecurityScan.objects.get().grade, "")

    def test_admin_scan_all(self, scan):
        self.client.force_login(self.admin)
        r = self.client.post(reverse("domains:security_scan_all"), follow=True)
        self.assertContains(r, "Scanned 2 domain(s); 2 graded")
        self.assertEqual(sorted(c.args[0] for c in scan.call_args_list), ["a.example.com", "b.example.com"])
        self.assertTrue(AuditEvent.objects.filter(action="run", details__check="security_scan_all").exists())

    def test_get_not_allowed_and_inactive_or_foreign_domains_404(self, scan):
        self.client.force_login(self.operator)
        self.assertEqual(self.client.get(reverse("domains:security_scan", args=[self.a.pk])).status_code, 405)
        self.assertEqual(self.client.post(reverse("domains:security_scan", args=[self.off.pk])).status_code, 404)
        self.assertEqual(self.client.post(reverse("domains:security_scan", args=[self.other.pk])).status_code, 404)
        scan.assert_not_called()

    def test_csrf_enforced(self, scan):
        c = Client(enforce_csrf_checks=True)
        c.force_login(self.operator)
        self.assertEqual(c.post(reverse("domains:security_scan", args=[self.a.pk])).status_code, 403)
        page = c.get(reverse("domains:security"))
        token = page.cookies["csrftoken"].value
        r = c.post(reverse("domains:security_scan", args=[self.a.pk]), {"csrfmiddlewaretoken": token})
        self.assertEqual(r.status_code, 302)
        scan.assert_called_once()


class ExistingMutationPermissionTests(InsightBase):
    """The older Domains mutations now use core.access and write audit rows."""

    def test_membership_operator_can_toggle_and_viewer_cannot(self):
        site = Site.objects.create(name="Mumbai", code="mumbai")
        op = User.objects.create_user("site-op", password="x" * 14)
        Membership.objects.create(user=op, site=None, role="operator")
        self.client.force_login(self.viewer)
        r = self.client.post(reverse("domains:toggle", args=[self.a.pk]))
        self.assertEqual(r.status_code, 302)
        self.a.refresh_from_db()
        self.assertTrue(self.a.is_active)
        self.client.force_login(op)
        self.client.post(reverse("domains:toggle", args=[self.a.pk]))
        self.a.refresh_from_db()
        self.assertFalse(self.a.is_active)
        self.assertTrue(AuditEvent.objects.filter(action="update", object_id=str(self.a.pk), actor=op).exists())
        self.assertTrue(site.pk)

    @mock.patch("probes.runner.run_domain_checks")
    def test_add_domain_is_audited(self, run):
        self.client.force_login(self.operator)
        r = self.client.post(reverse("domains:list"), {"hostname": "new.example.com", "domain_type": "API", "site_key": "Mumbai",
                                                       "check_interval_seconds": 300, "monitor_enabled": "on"})
        self.assertEqual(r.status_code, 302)
        d = Domain.objects.get(hostname="new.example.com")
        self.assertTrue(AuditEvent.objects.filter(action="create", object_id=str(d.pk)).exists())
        run.assert_called_once()

    def test_viewer_json_actions_are_refused(self):
        self.client.force_login(self.viewer)
        r = self.client.post(reverse("domains:run_all"), HTTP_X_CSRFTOKEN="x")
        self.assertEqual(r.status_code, 403)

    def test_site_scoping(self):
        Site.objects.create(name="Mumbai", code="mumbai")
        u = User.objects.create_user("mumbai-viewer", password="x" * 14)
        Membership.objects.create(user=u, site=Site.objects.get(name="Mumbai"), role="viewer")
        Domain.objects.create(tenant_key="default", hostname="global.example.com", site_key="All Sites")
        self.client.force_login(u)
        r = self.client.get(reverse("domains:uptime"))
        self.assertEqual({d.hostname for d in r.context["page"]}, {"a.example.com", "global.example.com"})
        rows = json.loads(self.client.get(reverse("domains:export_reports") + "?format=json").content)["results"]
        self.assertEqual({x["hostname"] for x in rows}, {"a.example.com", "global.example.com"})

    def test_api_contract_still_staff_only(self):
        self.client.force_login(self.viewer)
        self.assertEqual(self.client.get("/configuration/domains/api/?tenant=default").status_code, 302)
        self.client.force_login(self.operator)
        r = self.client.get("/configuration/domains/api/?tenant=default")
        self.assertEqual({x["hostname"] for x in r.json()["results"]}, {"a.example.com", "b.example.com", "off.example.com"})
        self.assertEqual(self.client.get("/configuration/domains/api/").status_code, 400)


class ExportReportTests(InsightBase):
    def test_csv_and_json(self):
        security.save_scan(self.a, facts(hostname=self.a.hostname))
        self.client.force_login(self.viewer)
        r = self.client.get(reverse("domains:export_reports") + "?format=csv")
        self.assertEqual(r["Content-Type"], "text/csv")
        self.assertIn("attachment; filename=\"domains-report-", r["Content-Disposition"])
        rows = list(csv.DictReader(io.StringIO(r.content.decode())))
        self.assertEqual([x["hostname"] for x in rows], ["b.example.com", "a.example.com"])   # site, then hostname
        a = next(x for x in rows if x["hostname"] == "a.example.com")
        self.assertEqual((a["status"], a["dns_status"], a["ssl_status"], a["uptime_7d"], a["security_grade"]),
                         ("up", "Resolved", "Valid", "100.0", "A"))
        self.assertEqual(a["ssl_days_left"], "59")
        r = self.client.get(reverse("domains:export_reports") + "?format=json&type=API")
        body = json.loads(r.content)
        self.assertEqual((body["count"], body["filters"]), (1, {"type": "API", "active": "1"}))
        self.assertEqual(body["results"][0]["security_score"], 100)
        self.assertEqual(AuditEvent.objects.filter(action="export").count(), 2)

    def test_filters_and_inactive(self):
        self.client.force_login(self.viewer)
        body = self.client.get(reverse("domains:export_reports") + "?format=json&site=Mumbai&active=all").json()
        self.assertEqual({x["hostname"] for x in body["results"]}, {"a.example.com", "off.example.com"})
        body = self.client.get(reverse("domains:export_reports") + "?format=json&active=0").json()
        self.assertEqual([x["hostname"] for x in body["results"]], ["off.example.com"])

    def test_printable_summary(self):
        self.client.force_login(self.viewer)
        r = self.client.get(reverse("domains:export_reports") + "?site=DR%20Site")
        self.assertEqual(r.context["k"]["total"], 1)
        self.assertEqual(r.context["k"]["down"], 1)
        self.assertContains(r, "data-print")
        self.assertContains(r, "site = DR Site")
        self.assertContains(r, "format=csv")
        self.assertContains(r, "format=json")


class SeedCommandTests(TestCase):
    def test_seed_is_idempotent_and_removable(self):
        out = io.StringIO()
        call_command("seed_domainmonitor", stdout=out)
        n = Domain.objects.filter(description__startswith="Example:").count()
        self.assertGreaterEqual(n, 5)
        call_command("seed_domainmonitor", stdout=out)
        self.assertEqual(Domain.objects.filter(description__startswith="Example:").count(), n)
        self.assertFalse(DomainCheck.objects.exists())          # no invented history
        self.assertFalse(DomainSecurityScan.objects.exists())
        real = Domain.objects.create(tenant_key="default", hostname="real.example.net")
        call_command("seed_domainmonitor", "--remove", stdout=out)
        self.assertEqual(list(Domain.objects.all()), [real])

    @mock.patch.object(security, "scan_host", side_effect=lambda host: facts(hostname=host, headers=dict(GOOD_HEADERS)))
    @mock.patch("probes.runner.run_domain_checks")
    def test_seed_check_runs_real_probes(self, run, scan):
        call_command("seed_domainmonitor", "--check", stdout=io.StringIO())
        run.assert_called_once()
        self.assertEqual(DomainSecurityScan.objects.count(), Domain.objects.count())
