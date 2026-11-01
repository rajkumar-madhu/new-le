import csv
import io
from datetime import datetime, timedelta
from unittest import skipUnless

from django.contrib.auth import get_user_model
from django.core import mail
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from core.models import AuditEvent, Event, Membership, Site
from domainmonitor.models import Domain, DomainCheck
from urlchecker.models import UrlCheck, UrlResult

from . import analytics as an
from . import registry, scheduler
from .models import ReportRun, ScheduledReport

User = get_user_model()


def _has_model(app_label, model):
    from django.apps import apps
    try:
        apps.get_model(app_label, model)
        return True
    except LookupError:
        return False


HAS_SD = _has_model("servicedesk", "Ticket")


class _SD:
    """servicedesk.services, imported lazily so these tests also run where Service Desk is not built."""
    def __getattr__(self, name):
        from servicedesk import services
        return getattr(services, name)


sd = _SD()
needs_sd = skipUnless(HAS_SD, "servicedesk not installed")
PW = "Corr3ct-horse-battery"


def _csv(resp):
    return list(csv.reader(io.StringIO(resp.content.decode())))


class Base(TestCase):
    def setUp(self):
        self.mum = Site.objects.create(name="Mumbai", code="mum")
        self.del_ = Site.objects.create(name="Delhi", code="del")
        self.admin = User.objects.create_superuser("root", "root@example.com", PW)
        self.op = User.objects.create_user("op", "op@example.com", PW, is_staff=True)
        self.viewer = User.objects.create_user("viewer", "viewer@example.com", PW)
        Membership.objects.create(user=self.viewer, site=self.mum, role="viewer")
        now = timezone.now()
        self.u_mum = UrlCheck.objects.create(name="Mumbai portal", url="https://mum.example.com/", site="Mumbai")
        self.u_del = UrlCheck.objects.create(name="Delhi portal", url="https://del.example.com/", site="Delhi")
        for i in range(10):
            at = now - timedelta(hours=i + 1)
            UrlResult.objects.create(url_check=self.u_mum, checked_at=at, status="down" if i < 2 else "online", response_ms=100 + i)
            UrlResult.objects.create(url_check=self.u_del, checked_at=at, status="online", response_ms=50)
        self.dom = Domain.objects.create(tenant_key="default", site_key="Mumbai", hostname="shop.example.com",
                                         ssl_expires_at=now + timedelta(days=10), ssl_status="Expiring")
        for i in range(4):
            DomainCheck.objects.create(domain=self.dom, checked_at=now - timedelta(hours=i + 1), up=i != 0,
                                       dns_status="Resolved", ssl_status="Valid", response_ms=80)


class CsvSafetyTests(TestCase):
    def test_formulas_are_neutralised_numbers_kept(self):
        self.assertEqual(registry.csv_safe("=HYPERLINK(\"x\")"), "'=HYPERLINK(\"x\")")
        self.assertEqual(registry.csv_safe("+cmd"), "'+cmd")
        self.assertEqual(registry.csv_safe("@SUM(A1)"), "'@SUM(A1)")
        self.assertEqual(registry.csv_safe("-5"), "-5")
        self.assertEqual(registry.csv_safe(3.5), "3.5")
        self.assertEqual(registry.csv_safe(None), "")


class RegistryTests(Base):
    def test_every_report_generates(self):
        start, end = registry.period(7)
        for key, report in registry.REPORTS.items():
            rows, error = registry.generate(report, registry.Ctx(start, end, self.admin))
            if report.available():
                self.assertEqual(error, "", key)
                for r in rows:
                    self.assertEqual(len(r), len(report.columns), key)

    def test_url_availability_numbers_and_site_scope(self):
        start, end = registry.period(1)
        rows, _ = registry.generate(registry.REPORTS["url_availability"], registry.Ctx(start, end, self.viewer))
        self.assertEqual([r[0] for r in rows], ["Mumbai portal"])  # Delhi hidden from a Mumbai viewer
        r = rows[0]
        self.assertEqual(r[4], 10)        # samples
        self.assertEqual(r[5], 80.0)      # availability %
        self.assertEqual(r[6], 2)         # down samples

    @needs_sd
    def test_incident_and_sla_rows(self):
        t = sd.create_ticket(user=self.op, kind="incident", title="Portal down", priority="P1", site="Mumbai")
        t.acknowledged_at = t.opened_at + timedelta(minutes=10)
        t.resolved_at = t.opened_at + timedelta(minutes=70)
        t.save()
        start, end = registry.period(7)
        rows, _ = registry.generate(registry.REPORTS["incidents"], registry.Ctx(start, end, self.admin))
        self.assertEqual(rows[0][0], t.number)
        self.assertEqual(rows[0][13], 10.0)
        self.assertEqual(rows[0][14], 70.0)
        sla = {r[0]: r for r in registry.generate(registry.REPORTS["sla"], registry.Ctx(start, end, self.admin))[0]}
        self.assertEqual(sla["P1"][1], 1)
        self.assertEqual(sla["P1"][8], 70.0)

    def test_ssl_expiry_horizon(self):
        now = timezone.now()
        rows, _ = registry.generate(registry.REPORTS["ssl_expiry"], registry.Ctx(now - timedelta(days=30), now))
        self.assertEqual([r[0] for r in rows], ["shop.example.com"])
        rows, _ = registry.generate(registry.REPORTS["ssl_expiry"], registry.Ctx(now - timedelta(days=5), now))
        self.assertEqual(rows, [])


class ViewTests(Base):
    def test_index_lists_reports_and_hides_admin_ones(self):
        self.client.force_login(self.viewer)
        resp = self.client.get(reverse("reports:index"))
        self.assertContains(resp, "URL availability")
        self.assertNotContains(resp, "Audit trail")
        self.assertNotContains(resp, "Schedule a report")
        self.assertEqual(self.client.get(reverse("reports:preview", args=["audit"])).status_code, 403)
        self.assertEqual(self.client.get(reverse("reports:preview", args=["nope"])).status_code, 404)

    def test_preview_and_download(self):
        UrlCheck.objects.create(name="=cmd|' /C calc'!A0", url="https://x.example.com/", site="Mumbai")
        self.client.force_login(self.viewer)
        resp = self.client.get(reverse("reports:preview", args=["url_availability"]), {"days": 1})
        self.assertContains(resp, "Mumbai portal")
        self.assertNotContains(resp, "Delhi portal")
        resp = self.client.get(reverse("reports:download", args=["url_availability"]), {"days": 1, "site": "Mumbai"})
        self.assertEqual(resp["Content-Type"], "text/csv; charset=utf-8")
        rows = _csv(resp)
        self.assertEqual(rows[0], registry.REPORTS["url_availability"].columns)
        names = [r[0] for r in rows[1:]]
        self.assertIn("Mumbai portal", names)
        self.assertIn("'=cmd|' /C calc'!A0", names)
        run = ReportRun.objects.get()
        self.assertEqual((run.report_key, run.rows, run.site, run.requested_by), ("url_availability", 2, "Mumbai", self.viewer))
        self.assertTrue(AuditEvent.objects.filter(action="export", object_type="report", details__report="url_availability").exists())

    def test_site_param_outside_scope_is_ignored(self):
        self.client.force_login(self.viewer)
        rows = _csv(self.client.get(reverse("reports:download", args=["url_availability"]), {"days": 1, "site": "Delhi"}))
        self.assertEqual([r[0] for r in rows[1:]], ["Mumbai portal"])

    def test_custom_date_range(self):
        self.client.force_login(self.admin)
        today = timezone.localdate()
        resp = self.client.get(reverse("reports:preview", args=["events"]),
                               {"from": (today - timedelta(days=3)).isoformat(), "to": today.isoformat()})
        self.assertContains(resp, (today - timedelta(days=3)).strftime("%d %b %Y"))

    @needs_sd
    def test_analytics_page(self):
        sd.create_ticket(user=self.op, kind="incident", title="Disk full", priority="P2", site="Mumbai", ci_name="db01")
        Event.objects.create(source="urlchecker", title="Down", severity="critical", site="Mumbai")
        self.client.force_login(self.admin)
        for rng in ("7", "30", "90", "bogus"):
            resp = self.client.get(reverse("reports:analytics"), {"range": rng})
            self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "MTTA")
        self.assertContains(resp, "db01")
        self.assertContains(resp, 'data-src="d-av"')

    @needs_sd
    def test_analytics_empty_database(self):
        UrlResult.objects.all().delete()
        DomainCheck.objects.all().delete()
        self.client.force_login(self.viewer)
        resp = self.client.get(reverse("reports:analytics"))
        self.assertContains(resp, "No check results in this period")
        self.assertContains(resp, "No incidents in this period")


class AnalyticsTests(Base):
    def test_availability_series_and_scope(self):
        w = an.Window(7)
        av = an.availability(self.viewer, w)
        self.assertEqual(av["url"], 80.0)          # only Mumbai results count for this viewer
        self.assertEqual(av["domain"], 75.0)
        self.assertEqual(len(av["chart"]["series"][0]["values"]), 7)
        self.assertIsNone(av["chart"]["series"][0]["values"][0])   # days without data are gaps
        self.assertEqual(av["least"][0]["name"], "shop.example.com")

    @needs_sd
    def test_service_desk_kpis(self):
        t = sd.create_ticket(user=self.op, kind="incident", title="x", priority="P3", site="Mumbai")
        t.acknowledged_at = t.opened_at + timedelta(minutes=30)
        t.save()
        k = an.service_desk(self.admin, an.Window(7))
        self.assertEqual(k["kpi"]["opened"], 1)
        self.assertEqual(k["kpi"]["mtta"], 30.0)
        self.assertEqual(k["open_now"], 1)
        self.assertIsNone(k["change"]["opened"])   # no previous incidents: no misleading percentage


@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
class ScheduleTests(Base):
    def _schedule(self, **kw):
        defaults = dict(name="Weekly availability", report_key="url_availability", window_days=1,
                        frequency="weekly", send_hour=7, recipients="noc@example.com, cio@example.com", owner=self.op)
        defaults.update(kw)
        return ScheduledReport.objects.create(**defaults)

    def test_next_run_computation(self):
        s = ScheduledReport(frequency="weekly", send_hour=7)
        nxt = s.compute_next_run(timezone.make_aware(datetime(2026, 11, 4, 12, 0)))   # a Wednesday
        self.assertEqual((nxt.weekday(), nxt.hour), (0, 7))
        self.assertEqual(timezone.localdate(nxt).day, 9)
        s.frequency = "monthly"
        self.assertEqual(timezone.localdate(s.compute_next_run(timezone.make_aware(datetime(2026, 11, 1, 8, 0)))).isoformat(), "2026-12-01")
        s.frequency = "daily"
        self.assertEqual(s.compute_next_run(timezone.make_aware(datetime(2026, 11, 1, 6, 0))).hour, 7)

    def test_due_schedule_is_emailed_with_csv(self):
        s = self._schedule()
        ScheduledReport.objects.filter(pk=s.pk).update(next_run_at=timezone.now() - timedelta(minutes=1))
        self.assertEqual(scheduler.run_due_schedules(), "1 sent, 0 failed")
        self.assertEqual(len(mail.outbox), 1)
        msg = mail.outbox[0]
        self.assertEqual(msg.to, ["noc@example.com", "cio@example.com"])
        name, content, mime = msg.attachments[0]
        self.assertTrue(name.startswith("url_availability-"))
        self.assertIn("Mumbai portal", content)
        s.refresh_from_db()
        self.assertEqual(s.last_status, "ok")
        self.assertGreater(s.next_run_at, timezone.now())
        self.assertIsNone(scheduler.run_due_schedules())   # not due again

    def test_schedule_rows_follow_owner_scope(self):
        s = self._schedule(owner=self.viewer)
        scheduler.deliver(s)
        content = mail.outbox[0].attachments[0][1]
        self.assertIn("Mumbai portal", content)
        self.assertNotIn("Delhi portal", content)

    def test_failure_is_recorded_and_emitted(self):
        s = self._schedule(owner=None)
        run = scheduler.deliver(s)
        self.assertEqual(run.status, "failed")
        self.assertIn("owner", run.error)
        self.assertEqual(len(mail.outbox), 0)
        self.assertTrue(Event.objects.filter(source="reports", fingerprint=f"reports:schedule:{s.pk}").exists())

    def test_create_edit_send_delete_via_views(self):
        self.client.force_login(self.op)
        resp = self.client.post(reverse("reports:schedule_new"), {
            "name": "Daily availability", "report_key": "url_availability", "window_days": 1, "site": "", "frequency": "daily",
            "send_hour": 8, "recipients": "a@example.com\nb@example.com", "enabled": "on"})
        self.assertRedirects(resp, reverse("reports:index"))
        s = ScheduledReport.objects.get(name="Daily availability")
        self.assertEqual(s.owner, self.op)
        self.assertEqual(timezone.localtime(s.next_run_at).hour, 8)
        self.assertEqual(s.recipient_list(), ["a@example.com", "b@example.com"])
        resp = self.client.post(reverse("reports:schedule_edit", args=[s.pk]), {
            "name": "Daily availability", "report_key": "url_availability", "window_days": 2, "site": "", "frequency": "daily",
            "send_hour": 8, "recipients": "a@example.com"})   # enabled unchecked
        s.refresh_from_db()
        self.assertFalse(s.enabled)
        self.assertIsNone(s.next_run_at)
        self.client.post(reverse("reports:schedule_send", args=[s.pk]))
        self.assertEqual(len(mail.outbox), 1)
        self.client.post(reverse("reports:schedule_delete", args=[s.pk]))
        self.assertFalse(ScheduledReport.objects.filter(pk=s.pk).exists())
        self.assertEqual(AuditEvent.objects.filter(object_type="reports.scheduledreport").count(), 4)

    def test_validation_and_permissions(self):
        self.client.force_login(self.op)
        resp = self.client.post(reverse("reports:schedule_new"), {
            "name": "x", "report_key": "audit", "window_days": 1, "frequency": "daily", "send_hour": 8,
            "recipients": "not-an-email"})
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Choose a report you are allowed to run")
        self.assertContains(resp, "not a valid e-mail address")
        other = self._schedule(owner=self.admin)
        self.assertEqual(self.client.get(reverse("reports:schedule_edit", args=[other.pk])).status_code, 403)
        self.assertEqual(self.client.post(reverse("reports:schedule_delete", args=[other.pk])).status_code, 403)
        self.client.force_login(self.viewer)
        self.assertEqual(self.client.get(reverse("reports:schedule_new")).status_code, 403)
