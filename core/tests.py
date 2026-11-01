from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase, override_settings
from django.urls import reverse

from core import access, jobs
from core.audit import audit
from core.events import emit, event_emitted
from core.models import AuditEvent, Event, Membership, Site


class AccessTests(TestCase):
    def setUp(self):
        self.mum = Site.objects.create(name="Mumbai (NSE)", code="mumbai-nse")
        self.dr = Site.objects.create(name="DR Site", code="dr")

    def test_defaults_without_memberships(self):
        viewer = User.objects.create_user("v")
        staff = User.objects.create_user("s", is_staff=True)
        root = User.objects.create_superuser("r", "r@example.com", "x")
        self.assertEqual(access.role_for(viewer), "viewer")
        self.assertEqual(access.role_for(staff), "operator")
        self.assertEqual(access.role_for(root), "admin")
        self.assertFalse(access.can(viewer, "operate"))
        self.assertTrue(access.can(staff, "operate"))
        self.assertIsNone(access.visible_sites(viewer))

    def test_site_scoped_membership(self):
        u = User.objects.create_user("op")
        Membership.objects.create(user=u, site=self.mum, role="operator")
        self.assertEqual(access.visible_sites(u), {"Mumbai (NSE)"})
        self.assertTrue(access.can(u, "operate", "Mumbai (NSE)"))
        self.assertFalse(access.can(u, "operate", "DR Site"))
        self.assertFalse(access.can(u, "admin"))

    def test_global_membership(self):
        u = User.objects.create_user("adm")
        Membership.objects.create(user=u, site=None, role="admin")
        self.assertIsNone(access.visible_sites(u))
        self.assertTrue(access.can(u, "admin", "DR Site"))


class EventAuditTests(TestCase):
    @override_settings(INCIDENT_AUTO_CREATE=False)  # isolate from the Service Desk listener
    def test_emit_sends_signal_and_survives_broken_listener(self):
        seen = []

        def good(sender, event, **kw):
            seen.append(event.title)

        def bad(sender, event, **kw):
            raise RuntimeError("boom")
        event_emitted.connect(good)
        event_emitted.connect(bad)
        try:
            ev = emit("test", "Thing down", severity="critical", site="DR Site", fingerprint="t:1", extra=1)
        finally:
            event_emitted.disconnect(good)
            event_emitted.disconnect(bad)
        self.assertEqual(seen, ["Thing down"])
        self.assertEqual(Event.objects.get().data, {"extra": 1})
        self.assertEqual(ev.severity, "critical")

    def test_audit_records_actor(self):
        u = User.objects.create_user("a")
        req = mock.Mock(user=u, META={"REMOTE_ADDR": "10.0.0.5"})
        audit(req, "create", object_type="thing", name="x")
        a = AuditEvent.objects.get()
        self.assertEqual((a.actor_name, a.source_ip, a.details), ("a", "10.0.0.5", {"name": "x"}))

    @override_settings(NOTIFY_WEBHOOK_URLS=["http://hook.example/x"], NOTIFY_EMAILS=[], INCIDENT_AUTO_CREATE=False)
    def test_webhook_notification_for_critical(self):
        with mock.patch("core.notify._post") as post:
            emit("test", "Down", severity="critical")
            emit("test", "Just info", severity="info")
        self.assertEqual(post.call_count, 1)


class JobTests(TestCase):
    def test_registry_runs_due_jobs_once_per_interval(self):
        calls = []
        jobs.register("t.job", 60, lambda: calls.append(1) or "ran")
        try:
            self.assertEqual(jobs.run_due(now=1000.0).get("t.job"), "ran")
            self.assertNotIn("t.job", jobs.run_due(now=1030.0))
            self.assertIn("t.job", jobs.run_due(now=1061.0))
        finally:
            jobs.JOBS.pop("t.job")
        self.assertEqual(len(calls), 2)


class OverviewTests(TestCase):
    """Dashboard, global search and the shell context draw on every installed module, limited to the user's sites."""

    def setUp(self):
        from network.models import Device
        from tcpcheck.models import TcpCheck
        from urlchecker.models import UrlCheck
        self.mum = Site.objects.create(name="Mumbai", code="mum")
        self.dr = Site.objects.create(name="DR Site", code="dr")
        self.admin = User.objects.create_superuser("root", "root@example.com", "Corr3ct-horse-battery")
        self.viewer = User.objects.create_user("viewer", "v@example.com", "Corr3ct-horse-battery")
        Membership.objects.create(user=self.viewer, site=self.mum, role="viewer")
        self.op = User.objects.create_user("op", "op@example.com", "Corr3ct-horse-battery")
        Membership.objects.create(user=self.op, site=None, role="operator")
        UrlCheck.objects.create(name="Portal", url="https://portal.example.com/", site="Mumbai", last_status="down")
        Device.objects.create(name="core-sw-01", device_type="switch", mgmt_ip="10.0.0.1", site="Mumbai", status="down",
                              serial="SN-777")
        Device.objects.create(name="dr-fw-01", device_type="firewall", mgmt_ip="10.9.0.1", site="DR Site", status="down")
        TcpCheck.objects.create(name="Oracle", host="db.example.com", port=1521, site="Mumbai", last_status="degraded")

    def test_problem_count_and_sites_are_scoped(self):
        from . import overview
        self.assertEqual(overview.problem_count(self.admin), 4)
        self.assertEqual(overview.problem_count(self.viewer), 3)   # the DR firewall is outside Mumbai
        self.assertEqual(overview.site_names(self.admin), ["DR Site", "Mumbai"])
        self.assertEqual(overview.site_names(self.viewer), ["Mumbai"])
        kinds = {p["kind"] for p in overview.problems(self.viewer)}
        self.assertEqual(kinds, {"URL", "Device", "TCP"})

    def test_dashboard_lists_cross_module_problems(self):
        self.client.force_login(self.viewer)
        resp = self.client.get(reverse("dashboard"))
        self.assertContains(resp, "core-sw-01")
        self.assertContains(resp, "Oracle (db.example.com:1521)")
        self.assertNotContains(resp, "dr-fw-01")
        self.assertContains(resp, "Devices up")

    def test_recent_events_render_in_one_wrapping_cell(self):
        # The events panel is a narrow column: the time sits on the source line and the title cell may wrap,
        # instead of three nowrap cells that were clipped by the table's scroll box.
        emit("bodeod", "BOD validation completed with warnings", severity="warning", site="Mumbai")
        self.client.force_login(self.admin)
        resp = self.client.get(reverse("dashboard"))
        self.assertContains(resp, '<td class="wrap ev"><span class="t-mute small">bodeod · ')
        self.assertContains(resp, "BOD validation completed with warnings</td>")

    def test_search_covers_devices_and_respects_sites(self):
        self.client.force_login(self.viewer)
        resp = self.client.get(reverse("search"), {"q": "SN-777"})
        self.assertContains(resp, "core-sw-01")
        resp = self.client.get(reverse("search"), {"q": "fw-01"})
        self.assertNotContains(resp, "dr-fw-01")
        self.assertContains(resp, "Network devices (0)")

    def test_shell_shows_membership_role_and_badge(self):
        self.client.force_login(self.op)
        resp = self.client.get(reverse("dashboard"))
        self.assertEqual(resp.context["le_role"], "Operator")
        self.assertEqual(resp.context["le_problem_count"], 4)
        self.assertTrue(resp.context["le_admin_url"])
