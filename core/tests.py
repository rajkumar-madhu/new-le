from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase, override_settings

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

    @override_settings(NOTIFY_WEBHOOK_URLS=["http://hook.example/x"], NOTIFY_EMAILS=[])
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
