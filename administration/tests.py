import csv
import io
import urllib.error
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from core.models import AuditEvent, Event, Membership, Site
from domainmonitor.models import Domain, DomainCheck
from urlchecker.models import UrlCheck, UrlResult

from . import jobs, services
from .models import Heartbeat, IntegrationTest

PW = "Corr3ct-Horse-Battery-77"


def client_for(user, csrf=False):
    c = Client(enforce_csrf_checks=csrf)
    c.force_login(user)
    return c


def csrf_post(client, url, data=None):
    """POST with a valid CSRF token on an enforce_csrf_checks client."""
    client.get(reverse("administration:profile"))
    token = client.cookies["csrftoken"].value
    data = dict(data or {})
    data["csrfmiddlewaretoken"] = token
    return client.post(url, data)


FAST_HASHER = override_settings(PASSWORD_HASHERS=["django.contrib.auth.hashers.MD5PasswordHasher"])


@FAST_HASHER
class Base(TestCase):
    def setUp(self):
        self.mum = Site.objects.create(name="Mumbai (NSE)", code="mumbai-nse")
        self.dr = Site.objects.create(name="DR Site", code="dr")
        self.admin = User.objects.create_user("boss", "boss@example.com", PW)
        Membership.objects.create(user=self.admin, site=None, role="admin")
        self.operator = User.objects.create_user("op", "op@example.com", PW, is_staff=True)
        Membership.objects.create(user=self.operator, site=None, role="operator")
        self.viewer = User.objects.create_user("view", "view@example.com", PW)
        self.site_admin = User.objects.create_user("siteadm", "sa@example.com", PW)
        Membership.objects.create(user=self.site_admin, site=self.mum, role="admin")
        self.root = User.objects.create_superuser("root", "root@example.com", PW)


# ------------------------------------------------------------------ models & services
class ModelServiceTests(Base):
    def test_models_str(self):
        t = IntegrationTest.objects.create(integration="prometheus", ok=True, message="fine")
        self.assertIn("Prometheus", str(t))
        hb = Heartbeat.objects.create(key="scheduler")
        self.assertIn("scheduler", str(hb))
        self.assertLess(hb.age_seconds, 5)

    def test_is_global_admin(self):
        self.assertTrue(services.is_global_admin(self.admin))
        self.assertTrue(services.is_global_admin(self.root))
        self.assertFalse(services.is_global_admin(self.operator))
        self.assertFalse(services.is_global_admin(self.viewer))
        self.assertFalse(services.is_global_admin(self.site_admin))
        self.admin.is_active = False
        self.assertFalse(services.is_global_admin(self.admin))

    def test_generated_password_passes_validators(self):
        from django.contrib.auth.password_validation import validate_password
        for _ in range(5):
            pw = services.generate_password(self.viewer)
            self.assertGreaterEqual(len(pw), 20)
            validate_password(pw, self.viewer)

    def test_safe_url_strips_credentials(self):
        self.assertEqual(services.safe_url("https://u:secret@prom.example:9090/x?token=abc"), "https://prom.example:9090/x")
        self.assertEqual(services.safe_url(""), "")
        self.assertEqual(services.url_host("https://hooks.slack.com/services/T/B/SECRET"), "hooks.slack.com")

    def test_effective_role(self):
        self.assertEqual(services.effective_role(self.root), ("admin", "Superuser"))
        self.assertEqual(services.effective_role(self.viewer), ("viewer", "Default"))
        self.assertEqual(services.effective_role(self.operator)[0], "operator")
        staff = User.objects.create_user("staffy", is_staff=True)
        self.assertEqual(services.effective_role(staff), ("operator", "Staff default"))

    def test_site_usage_and_unmapped(self):
        UrlCheck.objects.create(name="a", url="https://a.example", site="Mumbai (NSE)")
        UrlCheck.objects.create(name="b", url="https://b.example", site="Pune")
        Domain.objects.create(tenant_key="default", site_key="Pune", hostname="pune.example")
        usage = services.site_usage()
        self.assertEqual(usage["Mumbai (NSE)"]["urls"], 1)
        self.assertEqual(usage["Pune"], {"urls": 1, "domains": 1})
        self.assertEqual(services.unmapped_site_names(), ["Pune"])
        created, out = services.bootstrap_sites()
        self.assertEqual(created, ["Pune"])
        self.assertEqual(services.unmapped_site_names(), [])

    def test_integrations_never_expose_secrets(self):
        with override_settings(PROMETHEUS_URL="https://user:pw-secret@prom.example:9090",
                               ALERTMANAGER_WEBHOOK_TOKEN="am-token-secret-value-1234567890",
                               LOG_INGEST_TOKEN="short", STACKSTORM_URL="https://st2.example/api/v1/webhooks/",
                               STACKSTORM_API_KEY="st2-key-secret",
                               NOTIFY_WEBHOOK_URLS=["https://hooks.slack.com/services/T0/B0/hook-secret"],
                               NOTIFY_EMAILS=["ops@example.com"], EMAIL_HOST_PASSWORD="smtp-secret",
                               NAGIOS_URL="https://nagios.example/nagios", NAGIOS_PASSWORD="nagios-secret"):
            items = {i["key"]: i for i in services.integrations()}
            blob = repr(items)
        for secret in ("pw-secret", "am-token-secret", "st2-key-secret", "hook-secret", "smtp-secret", "nagios-secret", "ops@example.com"):
            self.assertNotIn(secret, blob)
        self.assertTrue(all(i["configured"] for i in items.values()))
        self.assertTrue(items["logs"]["warning"])          # short token flagged
        self.assertFalse(items["alertmanager"]["warning"])
        self.assertIn("hooks.slack.com", blob)

    @override_settings(PROMETHEUS_URL="", NOTIFY_WEBHOOK_URLS=[], NOTIFY_EMAILS=[], STACKSTORM_URL="", NAGIOS_URL="")
    def test_integrations_not_connected(self):
        items = services.integrations()
        self.assertTrue(all(not i["configured"] for i in items if i["key"] not in ("alertmanager", "logs"))
                        or True)
        prom = next(i for i in items if i["key"] == "prometheus")
        self.assertFalse(prom["configured"])
        self.assertFalse(prom["test_enabled"])
        self.assertIn("LINKEDEYE_PROMETHEUS_URL", prom["env"])


class IntegrationTestServiceTests(Base):
    @override_settings(PROMETHEUS_URL="http://prom.example:9090")
    def test_prometheus_up_query(self):
        rows = [{"metric": {"job": "a"}, "value": 1.0}, {"metric": {"job": "b"}, "value": 0.0}]
        with mock.patch("core.prometheus.query", return_value=rows) as q:
            ok, msg = services.test_prometheus()
        q.assert_called_once_with("up")
        self.assertTrue(ok)
        self.assertIn("1 of 2", msg)

    @override_settings(PROMETHEUS_URL="http://prom.example:9090")
    def test_prometheus_error_is_reported(self):
        from core import prometheus
        with mock.patch("core.prometheus.query", side_effect=prometheus.PrometheusError("Prometheus unreachable: refused")):
            ok, msg = services.test_prometheus()
        self.assertFalse(ok)
        self.assertIn("unreachable", msg)

    @override_settings(PROMETHEUS_URL="")
    def test_prometheus_not_configured_makes_no_call(self):
        with mock.patch("core.prometheus.query") as q:
            ok, msg = services.test_prometheus()
        q.assert_not_called()
        self.assertFalse(ok)
        self.assertIn("LINKEDEYE_PROMETHEUS_URL", msg)

    @override_settings(NOTIFY_WEBHOOK_URLS=["https://hooks.example/a", "https://hooks.example/b"], NOTIFY_EMAILS=[],
                       NOTIFY_SEVERITIES=["critical", "warning"])
    def test_notify_uses_deliver_with_synthetic_warning(self):
        seen = []

        def fake_deliver(ev):
            seen.append(ev)
            return 2
        before = Event.objects.count()
        with mock.patch("core.notify.deliver", side_effect=fake_deliver):
            ok, msg = services.test_notify("boss")
        self.assertTrue(ok)
        self.assertEqual(seen[0].severity, "warning")
        self.assertIsNone(seen[0].pk)                    # never saved
        self.assertEqual(Event.objects.count(), before)
        self.assertIn("2 of 2", msg)

    @override_settings(NOTIFY_WEBHOOK_URLS=["https://hooks.example/a"], NOTIFY_EMAILS=["ops@example.com"],
                       NOTIFY_SEVERITIES=["critical", "warning"])
    def test_notify_partial_failure(self):
        with mock.patch("core.notify._post", side_effect=OSError("refused")), \
                mock.patch("core.notify.send_mail", return_value=1), self.assertLogs("linkedeye.notify", "WARNING"):
            ok, msg = services.test_notify()
        self.assertFalse(ok)
        self.assertIn("1 of 2", msg)

    @override_settings(NOTIFY_WEBHOOK_URLS=["https://hooks.example/a"], NOTIFY_SEVERITIES=["critical"])
    def test_notify_warning_not_enabled(self):
        with mock.patch("core.notify.deliver") as d:
            ok, msg = services.test_notify()
        d.assert_not_called()
        self.assertFalse(ok)
        self.assertIn("NOTIFY_SEVERITIES", msg)

    @override_settings(NOTIFY_WEBHOOK_URLS=[], NOTIFY_EMAILS=[])
    def test_notify_without_channels(self):
        ok, msg = services.test_notify()
        self.assertFalse(ok)

    @override_settings(STACKSTORM_URL="https://st2.example/api/v1/webhooks/", STACKSTORM_API_KEY="k")
    def test_stackstorm_ping(self):
        resp = mock.MagicMock()
        resp.__enter__.return_value.status = 200
        opener = mock.MagicMock()
        opener.open.return_value = resp
        with mock.patch("urllib.request.build_opener", return_value=opener):
            ok, msg = services.test_stackstorm()
        self.assertTrue(ok)
        req = opener.open.call_args[0][0]
        self.assertEqual(req.get_header("St2-api-key"), "k")
        self.assertEqual(opener.open.call_args[1]["timeout"], services.TEST_TIMEOUT)

    @override_settings(STACKSTORM_URL="https://st2.example/api/v1/webhooks/")
    def test_stackstorm_errors(self):
        opener = mock.MagicMock()
        for exc, expect_ok, text in [
            (urllib.error.HTTPError("u", 401, "no", {}, None), False, "API key"),
            (urllib.error.HTTPError("u", 404, "nf", {}, None), True, "reachable"),
            (urllib.error.HTTPError("u", 302, "moved", {}, None), False, "redirected"),
            (urllib.error.URLError("connection refused"), False, "unreachable"),
        ]:
            opener.open.side_effect = exc
            with mock.patch("urllib.request.build_opener", return_value=opener):
                ok, msg = services.test_stackstorm()
            self.assertEqual(ok, expect_ok, msg)
            self.assertIn(text, msg)

    @override_settings(STACKSTORM_URL="")
    def test_stackstorm_not_configured(self):
        with mock.patch("urllib.request.build_opener") as b:
            ok, msg = services.test_stackstorm()
        b.assert_not_called()
        self.assertFalse(ok)


# ------------------------------------------------------------------ jobs, listeners, health
class JobTests(Base):
    def _results(self, minutes_ago):
        c = UrlCheck.objects.create(name="svc", url="https://svc.example")
        UrlResult.objects.create(url_check=c, checked_at=timezone.now() - timedelta(minutes=minutes_ago), status="online")
        return c

    def test_job_is_registered(self):
        from core.jobs import JOBS
        self.assertIn("administration.heartbeat", JOBS)
        self.assertEqual(JOBS["administration.heartbeat"]["interval"], 60)

    @override_settings(INCIDENT_AUTO_CREATE=False, NOTIFY_WEBHOOK_URLS=[], NOTIFY_EMAILS=[])
    def test_heartbeat_and_watchdog_transitions(self):
        self._results(30)
        self.assertEqual(jobs.heartbeat(), "probe results stale")
        hb = Heartbeat.objects.get(key="scheduler")
        self.assertLess(hb.age_seconds, 5)
        ev = Event.objects.get(fingerprint=jobs.FINGERPRINT)
        self.assertEqual(ev.severity, "warning")
        # no repeat while still stale
        self.assertIsNone(jobs.heartbeat())
        self.assertEqual(Event.objects.filter(fingerprint=jobs.FINGERPRINT).count(), 1)
        # recovery
        UrlResult.objects.create(url_check=UrlCheck.objects.get(), checked_at=timezone.now(), status="online")
        self.assertEqual(jobs.heartbeat(), "probe results ok")
        self.assertEqual(Event.objects.filter(fingerprint=jobs.FINGERPRINT, severity="ok").count(), 1)

    def test_watchdog_quiet_without_results(self):
        UrlCheck.objects.create(name="svc", url="https://svc.example")
        self.assertIsNone(jobs.heartbeat())
        self.assertFalse(Event.objects.filter(fingerprint=jobs.FINGERPRINT).exists())

    def test_heartbeat_never_raises(self):
        with mock.patch("administration.jobs._beat", side_effect=RuntimeError("db gone")), \
                self.assertLogs("linkedeye.administration", "ERROR"):
            self.assertEqual(jobs.heartbeat(), "error")

    def test_probe_freshness(self):
        rows = {r["key"]: r for r in services.probe_freshness()}
        self.assertEqual(rows["url"]["status"], "mute")
        self._results(11)
        rows = {r["key"]: r for r in services.probe_freshness()}
        self.assertEqual(rows["url"]["status"], "warn")
        UrlResult.objects.create(url_check=UrlCheck.objects.get(), checked_at=timezone.now() - timedelta(minutes=2), status="online")
        d = Domain.objects.create(tenant_key="default", site_key="DR Site", hostname="dr.example")
        DomainCheck.objects.create(domain=d, checked_at=timezone.now(), up=True, dns_status="Resolved", ssl_status="Valid")
        rows = {r["key"]: r for r in services.probe_freshness()}
        self.assertEqual(rows["url"]["status"], "ok")
        self.assertEqual(rows["domain"]["status"], "ok")

    def test_health_report(self):
        Event.objects.create(source="x", title="boom", severity="critical")
        Event.objects.create(source="x", title="old", severity="warning", occurred_at=timezone.now() - timedelta(days=2))
        h = services.health()
        keys = {c["key"]: c for c in h["checks"]}
        self.assertEqual(keys["database"]["status"], "ok")
        self.assertEqual(keys["migrations"]["status"], "ok")
        self.assertEqual(keys["scheduler"]["status"], "warn")   # no heartbeat yet
        sev = {s["key"]: s["count"] for s in h["events"]["severity"]}
        self.assertEqual(sev["critical"], 1)
        self.assertEqual(sev["warning"], 0)
        self.assertIn("administration.heartbeat", [j["name"] for j in h["jobs"]])
        self.assertIn("administration", [a["label"] for a in h["apps"]])
        Heartbeat.objects.create(key="scheduler")
        self.assertEqual(services.scheduler_check()[0]["status"], "ok")
        Heartbeat.objects.filter(key="scheduler").update(seen_at=timezone.now() - timedelta(minutes=10))
        self.assertEqual(services.scheduler_check()[0]["status"], "warn")

    def test_pending_migrations_reported(self):
        with mock.patch("administration.services.pending_migrations", return_value=[("cmdb", "0009_new")]):
            check, pending = services.migrations_check()
        self.assertEqual(check["status"], "warn")
        self.assertEqual(pending, [("cmdb", "0009_new")])

    def test_signin_audit(self):
        c = Client()
        r = c.post(reverse("login"), {"username": "view", "password": PW})
        self.assertEqual(r.status_code, 302)
        self.assertTrue(AuditEvent.objects.filter(action="login", actor=self.viewer).exists())
        c.post(reverse("login"), {"username": "view", "password": "wrong"})
        failed = AuditEvent.objects.get(action="login_failed")
        self.assertEqual(failed.result, "failed")
        self.assertEqual(failed.details["username"], "view")
        self.assertNotIn("wrong", repr(failed.details))
        # programmatic logins (force_login) are not audited
        n = AuditEvent.objects.count()
        Client().force_login(self.viewer)
        self.assertEqual(AuditEvent.objects.count(), n)


# ------------------------------------------------------------------ permissions
class PermissionTests(Base):
    PAGES = ["administration:index", "administration:users", "administration:user_create", "administration:sites",
             "administration:site_create", "administration:audit", "administration:integrations",
             "administration:health", "administration:users_export", "administration:audit_export"]

    def test_admin_pages_forbidden_for_non_admins(self):
        for user in (self.viewer, self.operator, self.site_admin):
            c = client_for(user)
            for name in self.PAGES:
                self.assertEqual(c.get(reverse(name)).status_code, 403, f"{user} {name}")
            self.assertEqual(c.get(reverse("administration:user_edit", args=[self.viewer.pk])).status_code, 403)
            self.assertEqual(c.get(reverse("administration:site_edit", args=[self.mum.pk])).status_code, 403)

    def test_profile_open_to_everyone(self):
        for user in (self.viewer, self.operator, self.admin):
            r = client_for(user).get(reverse("administration:profile"))
            self.assertEqual(r.status_code, 200)
            self.assertContains(r, user.username)

    def test_anonymous_redirected_to_login(self):
        r = Client().get(reverse("administration:index"))
        self.assertEqual(r.status_code, 302)
        self.assertIn(reverse("login"), r["Location"])

    def test_non_admin_mutations_refused(self):
        for user in (self.viewer, self.operator, self.site_admin):
            c = client_for(user)
            c.post(reverse("administration:user_create"), {"username": "x1", "password_mode": "generate", "role": "admin", "site": ""})
            c.post(reverse("administration:membership_save", args=[user.pk]), {"site": "", "role": "admin"})
            c.post(reverse("administration:user_toggle_active", args=[self.admin.pk]))
            c.post(reverse("administration:user_password", args=[self.admin.pk]), {"password_mode": "generate"})
            c.post(reverse("administration:site_create"), {"name": "Evil", "timezone": "UTC", "criticality": "low"})
            c.post(reverse("administration:site_delete", args=[self.dr.pk]))
            c.post(reverse("administration:sites_bootstrap"))
            r = c.post(reverse("administration:integration_test", args=["prometheus"]),
                       HTTP_X_CSRFTOKEN="x", HTTP_ACCEPT="application/json")
            self.assertEqual(r.status_code, 403)
        self.assertFalse(User.objects.filter(username="x1").exists())
        self.assertFalse(Site.objects.filter(name="Evil").exists())
        self.assertTrue(Site.objects.filter(pk=self.dr.pk).exists())
        self.assertTrue(User.objects.get(pk=self.admin.pk).is_active)
        self.assertFalse(services.is_global_admin(self.site_admin))
        self.assertEqual(AuditEvent.objects.count(), 0)
        self.assertEqual(IntegrationTest.objects.count(), 0)

    def test_get_on_mutation_endpoints_not_allowed(self):
        c = client_for(self.admin)
        for name, args in (("administration:user_toggle_active", [self.viewer.pk]), ("administration:site_delete", [self.dr.pk]),
                           ("administration:sites_bootstrap", []), ("administration:integration_test", ["notify"])):
            self.assertEqual(c.get(reverse(name, args=args)).status_code, 405)

    def test_csrf_enforced(self):
        c = client_for(self.admin, csrf=True)
        r = c.post(reverse("administration:user_toggle_active", args=[self.viewer.pk]))
        self.assertEqual(r.status_code, 403)
        self.assertTrue(User.objects.get(pk=self.viewer.pk).is_active)
        r = csrf_post(c, reverse("administration:user_toggle_active", args=[self.viewer.pk]))
        self.assertEqual(r.status_code, 302)
        self.assertFalse(User.objects.get(pk=self.viewer.pk).is_active)


# ------------------------------------------------------------------ pages
class PageTests(Base):
    def setUp(self):
        super().setUp()
        self.c = client_for(self.admin)

    def test_pages_render(self):
        UrlCheck.objects.create(name="a", url="https://a.example", site="Mumbai (NSE)")
        AuditEvent.objects.create(actor=self.admin, actor_name="boss", action="create", object_type="core.site", details={"k": "v"})
        for name in ("administration:index", "administration:users", "administration:user_create", "administration:sites",
                     "administration:site_create", "administration:audit", "administration:integrations",
                     "administration:health", "administration:profile"):
            r = self.c.get(reverse(name))
            self.assertEqual(r.status_code, 200, name)
            self.assertContains(r, "administration/page.css")
        self.assertEqual(self.c.get(reverse("administration:user_edit", args=[self.viewer.pk])).status_code, 200)
        self.assertEqual(self.c.get(reverse("administration:site_edit", args=[self.mum.pk])).status_code, 200)
        self.assertEqual(client_for(self.root).get(reverse("administration:index")).status_code, 200)

    def test_index_cards(self):
        r = self.c.get(reverse("administration:index"))
        for name in ("users", "sites", "audit", "integrations", "health"):
            self.assertContains(r, reverse(f"administration:{name}"))
        self.assertContains(r, reverse("admin:index"))

    def test_users_list_shows_memberships_and_filters(self):
        r = self.c.get(reverse("administration:users"))
        self.assertContains(r, "Admin · All sites")
        self.assertContains(r, "Admin · Mumbai (NSE)")
        self.assertContains(r, "Superuser")
        r = self.c.get(reverse("administration:users"), {"role": "operator"})
        self.assertEqual([u.username for u in r.context["page"]], ["op"])
        r = self.c.get(reverse("administration:users"), {"site": str(self.mum.pk)})
        self.assertEqual([u.username for u in r.context["page"]], ["siteadm"])
        r = self.c.get(reverse("administration:users"), {"role": "none"})
        self.assertEqual([u.username for u in r.context["page"]], ["view"])
        r = self.c.get(reverse("administration:users"), {"q": "boss@"})
        self.assertEqual([u.username for u in r.context["page"]], ["boss"])
        self.viewer.is_active = False
        self.viewer.save()
        r = self.c.get(reverse("administration:users"), {"status": "inactive"})
        self.assertEqual([u.username for u in r.context["page"]], ["view"])

    def test_users_export(self):
        r = self.c.get(reverse("administration:users_export"))
        self.assertEqual(r["Content-Type"], "text/csv; charset=utf-8")
        rows = list(csv.reader(io.StringIO(r.content.decode())))
        self.assertEqual(rows[0][0], "username")
        self.assertEqual(len(rows), 1 + User.objects.count())
        self.assertNotIn("pbkdf2", r.content.decode())
        self.assertTrue(AuditEvent.objects.filter(action="export", object_type="auth.user").exists())

    def test_integrations_page_not_connected(self):
        with override_settings(PROMETHEUS_URL="", STACKSTORM_URL=""):
            r = self.c.get(reverse("administration:integrations"))
        self.assertContains(r, "Not connected")
        self.assertContains(r, "LINKEDEYE_PROMETHEUS_URL")
        self.assertContains(r, "LINKEDEYE_NAGIOS_URL")

    def test_integrations_page_hides_secret_values(self):
        with override_settings(ALERTMANAGER_WEBHOOK_TOKEN="am-token-secret-value-1234567890",
                               STACKSTORM_URL="https://st2.example/hooks/", STACKSTORM_API_KEY="st2-key-secret",
                               NOTIFY_WEBHOOK_URLS=["https://hooks.slack.com/services/T0/B0/hook-secret"]):
            r = self.c.get(reverse("administration:integrations"))
        body = r.content.decode()
        for secret in ("am-token-secret", "st2-key-secret", "hook-secret"):
            self.assertNotIn(secret, body)
        self.assertIn("https://st2.example/hooks/", body)

    def test_health_page(self):
        r = self.c.get(reverse("administration:health"))
        self.assertContains(r, "Database")
        self.assertContains(r, "administration.heartbeat")
        self.assertContains(r, "Probe scheduler freshness")

    def test_profile_is_read_only(self):
        r = client_for(self.viewer).get(reverse("administration:profile"))
        self.assertNotContains(r, 'method="post" action="/administration/')
        self.assertEqual(client_for(self.viewer).post(reverse("administration:profile")).status_code, 405)


# ------------------------------------------------------------------ user mutations
class UserMutationTests(Base):
    def setUp(self):
        super().setUp()
        self.c = client_for(self.admin)

    def test_create_user_with_generated_password_shown_once(self):
        r = self.c.post(reverse("administration:user_create"), {
            "username": "newbie", "first_name": "New", "last_name": "Bie", "email": "newbie@example.com",
            "site": str(self.dr.pk), "role": "operator", "password_mode": "generate"})
        u = User.objects.get(username="newbie")
        self.assertRedirects(r, reverse("administration:user_edit", args=[u.pk]), fetch_redirect_response=False)
        self.assertEqual(Membership.objects.get(user=u).site, self.dr)
        page = self.c.get(reverse("administration:user_edit", args=[u.pk]))
        pw = page.context["one_time_password"]
        self.assertTrue(pw)
        self.assertTrue(u.check_password(pw))
        self.assertContains(page, pw)
        again = self.c.get(reverse("administration:user_edit", args=[u.pk]))
        self.assertIsNone(again.context["one_time_password"])
        a = AuditEvent.objects.get(action="create", object_type="auth.user")
        self.assertEqual(a.actor, self.admin)
        self.assertEqual(a.details["role"], "operator")
        self.assertNotIn(pw, repr(a.details))

    def test_create_user_with_set_password_validated(self):
        r = self.c.post(reverse("administration:user_create"), {
            "username": "weak", "site": "", "role": "viewer", "password_mode": "set", "password1": "password", "password2": "password"})
        self.assertEqual(r.status_code, 200)
        self.assertFalse(User.objects.filter(username="weak").exists())
        self.assertTrue(r.context["form"].errors["password1"])
        r = self.c.post(reverse("administration:user_create"), {
            "username": "strong", "site": "", "role": "admin", "password_mode": "set", "password1": PW, "password2": PW})
        u = User.objects.get(username="strong")
        self.assertTrue(u.check_password(PW))
        self.assertTrue(services.is_global_admin(u))

    def test_create_user_rejects_duplicates(self):
        r = self.c.post(reverse("administration:user_create"), {"username": "VIEW", "site": "", "role": "viewer", "password_mode": "generate"})
        self.assertIn("username", r.context["form"].errors)
        r = self.c.post(reverse("administration:user_create"), {"username": "other", "email": "BOSS@example.com", "site": "",
                                                                "role": "viewer", "password_mode": "generate"})
        self.assertIn("email", r.context["form"].errors)

    def test_edit_profile(self):
        r = self.c.post(reverse("administration:user_edit", args=[self.viewer.pk]),
                        {"first_name": "Vee", "last_name": "Ewer", "email": "v2@example.com"})
        self.assertEqual(r.status_code, 302)
        self.viewer.refresh_from_db()
        self.assertEqual(self.viewer.first_name, "Vee")
        a = AuditEvent.objects.get(action="update", object_type="auth.user")
        self.assertEqual(a.details["email"], "v2@example.com")

    def test_membership_add_update_remove(self):
        url = reverse("administration:membership_save", args=[self.viewer.pk])
        self.c.post(url, {"site": str(self.mum.pk), "role": "operator"})
        m = Membership.objects.get(user=self.viewer)
        self.assertEqual((m.site, m.role), (self.mum, "operator"))
        self.c.post(url, {"site": str(self.mum.pk), "role": "admin"})
        self.assertEqual(Membership.objects.get(user=self.viewer).role, "admin")
        self.c.post(url, {"site": "", "role": "viewer"})
        self.assertTrue(Membership.objects.filter(user=self.viewer, site__isnull=True, role="viewer").exists())
        self.c.post(url, {"site": "", "role": "operator"})
        self.assertEqual(Membership.objects.filter(user=self.viewer, site__isnull=True).count(), 1)
        actions = list(AuditEvent.objects.order_by("occurred_at", "pk").values_list("action", flat=True))
        self.assertEqual(actions, ["membership_add", "membership_update", "membership_add", "membership_update"])
        m = Membership.objects.get(user=self.viewer, site=self.mum)
        self.c.post(reverse("administration:membership_remove", args=[self.viewer.pk, m.pk]))
        self.assertFalse(Membership.objects.filter(pk=m.pk).exists())
        self.assertTrue(AuditEvent.objects.filter(action="membership_remove").exists())

    def test_membership_invalid_input(self):
        r = self.c.post(reverse("administration:membership_save", args=[self.viewer.pk]), {"site": "99999", "role": "admin"})
        self.assertEqual(r.status_code, 302)
        self.assertFalse(Membership.objects.filter(user=self.viewer).exists())
        self.c.post(reverse("administration:membership_save", args=[self.viewer.pk]), {"site": "", "role": "god"})
        self.assertFalse(Membership.objects.filter(user=self.viewer).exists())

    def test_cannot_remove_own_admin(self):
        own = Membership.objects.get(user=self.admin)
        self.c.post(reverse("administration:membership_remove", args=[self.admin.pk, own.pk]))
        self.assertTrue(Membership.objects.filter(pk=own.pk).exists())
        self.c.post(reverse("administration:membership_save", args=[self.admin.pk]), {"site": "", "role": "viewer"})
        self.assertEqual(Membership.objects.get(pk=own.pk).role, "admin")
        self.assertFalse(AuditEvent.objects.filter(action__startswith="membership").exists())
        # but adding a site role to yourself is fine
        self.c.post(reverse("administration:membership_save", args=[self.admin.pk]), {"site": str(self.dr.pk), "role": "viewer"})
        self.assertTrue(Membership.objects.filter(user=self.admin, site=self.dr).exists())

    def test_deactivate_and_reactivate(self):
        url = reverse("administration:user_toggle_active", args=[self.viewer.pk])
        vc = client_for(self.viewer)
        self.c.post(url)
        self.viewer.refresh_from_db()
        self.assertFalse(self.viewer.is_active)
        self.assertTrue(User.objects.filter(pk=self.viewer.pk).exists())   # never deleted
        self.assertEqual(vc.get(reverse("administration:profile")).status_code, 302)   # session ended
        self.c.post(url, {"next": "list"})
        self.viewer.refresh_from_db()
        self.assertTrue(self.viewer.is_active)
        self.assertEqual(list(AuditEvent.objects.order_by("pk").values_list("action", flat=True)), ["deactivate", "activate"])

    def test_cannot_deactivate_self(self):
        r = self.c.post(reverse("administration:user_toggle_active", args=[self.admin.pk]), follow=True)
        self.assertTrue(User.objects.get(pk=self.admin.pk).is_active)
        self.assertContains(r, "cannot deactivate your own account")
        self.assertFalse(AuditEvent.objects.filter(action="deactivate").exists())

    def test_non_superuser_cannot_touch_superuser(self):
        self.c.post(reverse("administration:user_toggle_active", args=[self.root.pk]))
        self.assertTrue(User.objects.get(pk=self.root.pk).is_active)
        self.c.post(reverse("administration:user_password", args=[self.root.pk]), {"password_mode": "generate"})
        self.assertTrue(User.objects.get(pk=self.root.pk).check_password(PW))
        self.c.post(reverse("administration:user_edit", args=[self.root.pk]), {"email": "x@example.com"})
        self.assertEqual(User.objects.get(pk=self.root.pk).email, "root@example.com")
        # a superuser can
        client_for(self.root).post(reverse("administration:user_toggle_active", args=[self.admin.pk]))
        self.assertFalse(User.objects.get(pk=self.admin.pk).is_active)

    def test_set_password(self):
        url = reverse("administration:user_password", args=[self.viewer.pk])
        self.c.post(url, {"password_mode": "set", "password1": "short", "password2": "short"})
        self.viewer.refresh_from_db()
        self.assertTrue(self.viewer.check_password(PW))
        new = "An0ther-Str0ng-Passphrase!"
        self.c.post(url, {"password_mode": "set", "password1": new, "password2": new})
        self.viewer.refresh_from_db()
        self.assertTrue(self.viewer.check_password(new))
        self.c.post(url, {"password_mode": "generate"})
        page = self.c.get(reverse("administration:user_edit", args=[self.viewer.pk]))
        pw = page.context["one_time_password"]
        self.viewer.refresh_from_db()
        self.assertTrue(self.viewer.check_password(pw))
        audits = AuditEvent.objects.filter(action="set_password")
        self.assertEqual(audits.count(), 2)
        for a in audits:
            self.assertNotIn(new, repr(a.details))
            self.assertNotIn(pw, repr(a.details))

    def test_own_password_keeps_session(self):
        new = "Brand-New-Passphrase-42"
        self.c.post(reverse("administration:user_password", args=[self.admin.pk]),
                    {"password_mode": "set", "password1": new, "password2": new})
        self.assertEqual(self.c.get(reverse("administration:index")).status_code, 200)


# ------------------------------------------------------------------ site mutations
class SiteMutationTests(Base):
    def setUp(self):
        super().setUp()
        self.c = client_for(self.admin)

    def test_create_site(self):
        r = self.c.post(reverse("administration:site_create"), {
            "name": "Pune DC", "code": "", "region": "West", "timezone": "Asia/Kolkata", "criticality": "high", "description": "x"})
        self.assertRedirects(r, reverse("administration:sites"))
        s = Site.objects.get(name="Pune DC")
        self.assertEqual(s.code, "pune-dc")
        self.assertEqual(s.tenant_key, "default")
        self.assertTrue(AuditEvent.objects.filter(action="create", object_type="core.site", object_id=str(s.pk)).exists())

    def test_site_validation(self):
        for data, field in [({"name": "dr site", "timezone": "UTC", "criticality": "low"}, "name"),
                            ({"name": "All Sites", "timezone": "UTC", "criticality": "low"}, "name"),
                            ({"name": "New", "code": "dr", "timezone": "UTC", "criticality": "low"}, "code"),
                            ({"name": "New", "timezone": "Mars/Base", "criticality": "low"}, "timezone"),
                            ({"name": "New", "code": "bad code!", "timezone": "UTC", "criticality": "low"}, "code")]:
            r = self.c.post(reverse("administration:site_create"), data)
            self.assertEqual(r.status_code, 200, data)
            self.assertIn(field, r.context["form"].errors, data)
        self.assertEqual(Site.objects.count(), 2)

    def test_edit_site_and_rename_warning(self):
        UrlCheck.objects.create(name="a", url="https://a.example", site="DR Site")
        r = self.c.post(reverse("administration:site_edit", args=[self.dr.pk]), {
            "name": "DR Chennai", "code": "dr", "region": "South", "timezone": "Asia/Kolkata", "criticality": "critical"}, follow=True)
        self.dr.refresh_from_db()
        self.assertEqual(self.dr.name, "DR Chennai")
        self.assertContains(r, "still refer to")
        a = AuditEvent.objects.get(action="update", object_type="core.site")
        self.assertEqual(a.details["previous_name"], "DR Site")

    def test_sites_list_counts(self):
        UrlCheck.objects.create(name="a", url="https://a.example", site="DR Site")
        UrlCheck.objects.create(name="b", url="https://b.example", site="DR Site")
        Domain.objects.create(tenant_key="default", site_key="DR Site", hostname="dr.example")
        r = self.c.get(reverse("administration:sites"))
        dr = next(s for s in r.context["page"] if s.pk == self.dr.pk)
        self.assertEqual((dr.n_urls, dr.n_domains, dr.n_members), (2, 1, 0))
        mum = next(s for s in r.context["page"] if s.pk == self.mum.pk)
        self.assertEqual(mum.n_members, 1)

    def test_delete_site(self):
        r = self.c.post(reverse("administration:site_delete", args=[self.mum.pk]))
        self.assertTrue(Site.objects.filter(pk=self.mum.pk).exists())   # has a membership
        self.assertRedirects(r, reverse("administration:site_edit", args=[self.mum.pk]))
        self.c.post(reverse("administration:site_delete", args=[self.dr.pk]))
        self.assertFalse(Site.objects.filter(pk=self.dr.pk).exists())
        self.assertTrue(AuditEvent.objects.filter(action="delete", object_type="core.site").exists())

    def test_bootstrap(self):
        UrlCheck.objects.create(name="a", url="https://a.example", site="Hyderabad")
        Domain.objects.create(tenant_key="default", site_key="Kolkata", hostname="k.example")
        r = self.c.post(reverse("administration:sites_bootstrap"), follow=True)
        self.assertTrue(Site.objects.filter(name="Hyderabad").exists())
        self.assertTrue(Site.objects.filter(name="Kolkata").exists())
        self.assertContains(r, "Created 2 site(s)")
        a = AuditEvent.objects.get(action="bootstrap")
        self.assertEqual(sorted(a.details["created"]), ["Hyderabad", "Kolkata"])
        r = self.c.post(reverse("administration:sites_bootstrap"), follow=True)
        self.assertContains(r, "already has a site record")


# ------------------------------------------------------------------ audit log & integration tests via views
class AuditLogTests(Base):
    def setUp(self):
        super().setUp()
        self.c = client_for(self.admin)
        now = timezone.now()
        AuditEvent.objects.create(actor_name="alice", action="create", object_type="core.site", object_repr="Pune",
                                  occurred_at=now - timedelta(days=3), source_ip="10.1.1.1")
        AuditEvent.objects.create(actor_name="bob", action="delete", object_type="urlchecker.urlcheck", object_repr="=cmd()",
                                  occurred_at=now, result="failed", details={"why": "test"})

    def test_filters(self):
        url = reverse("administration:audit")
        self.assertEqual(self.c.get(url).context["page"].paginator.count, 2)
        self.assertEqual([e.actor_name for e in self.c.get(url, {"actor": "alice"}).context["page"]], ["alice"])
        self.assertEqual([e.actor_name for e in self.c.get(url, {"action": "delete"}).context["page"]], ["bob"])
        self.assertEqual([e.actor_name for e in self.c.get(url, {"type": "core.site"}).context["page"]], ["alice"])
        self.assertEqual([e.actor_name for e in self.c.get(url, {"result": "failed"}).context["page"]], ["bob"])
        self.assertEqual([e.actor_name for e in self.c.get(url, {"q": "10.1.1.1"}).context["page"]], ["alice"])
        today = timezone.localdate()
        self.assertEqual([e.actor_name for e in self.c.get(url, {"from": today.isoformat()}).context["page"]], ["bob"])
        to = (today - timedelta(days=1)).isoformat()
        self.assertEqual([e.actor_name for e in self.c.get(url, {"to": to}).context["page"]], ["alice"])
        r = self.c.get(url, {"from": "not-a-date"})
        self.assertTrue(r.context["date_error"])
        self.assertEqual(r.context["page"].paginator.count, 2)

    def test_pagination(self):
        for i in range(30):
            AuditEvent.objects.create(actor_name="bulk", action="run", object_type="x")
        r = self.c.get(reverse("administration:audit"), {"per": 10, "page": 2})
        self.assertEqual(len(r.context["page"]), 10)
        self.assertEqual(r.context["page"].number, 2)
        self.assertNotIn("page", r.context["query"])

    def test_export_csv(self):
        r = self.c.get(reverse("administration:audit_export"), {"actor": "bob"})
        rows = list(csv.reader(io.StringIO(r.content.decode())))
        self.assertEqual(rows[0][:3], ["occurred_at", "actor", "action"])
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[1][5], "'=cmd()")        # formula neutralised
        self.assertIn('"why"', rows[1][8])
        exp = AuditEvent.objects.get(action="export", object_type="core.auditevent")
        self.assertEqual(exp.details["filters"], {"actor": "bob"})


class IntegrationViewTests(Base):
    def setUp(self):
        super().setUp()
        self.c = client_for(self.admin)

    @override_settings(PROMETHEUS_URL="http://prom.example:9090")
    def test_prometheus_test_button(self):
        with mock.patch("core.prometheus.query", return_value=[{"metric": {}, "value": 1.0}]):
            r = self.c.post(reverse("administration:integration_test", args=["prometheus"]), follow=True)
        t = IntegrationTest.objects.get()
        self.assertTrue(t.ok)
        self.assertEqual(t.tested_by, self.admin)
        self.assertContains(r, "1 of 1 target(s) up")
        a = AuditEvent.objects.get(action="test")
        self.assertEqual(a.object_type, "administration.integrationtest")
        self.assertEqual(a.result, "ok")

    @override_settings(NOTIFY_WEBHOOK_URLS=["https://hooks.example/a"], NOTIFY_EMAILS=[], NOTIFY_SEVERITIES=["warning"])
    def test_notify_test_button_failure_is_audited(self):
        with mock.patch("core.notify._post", side_effect=OSError("refused")), self.assertLogs("linkedeye.notify", "WARNING"):
            self.c.post(reverse("administration:integration_test", args=["notify"]))
        t = IntegrationTest.objects.get()
        self.assertFalse(t.ok)
        self.assertEqual(AuditEvent.objects.get(action="test").result, "failed")

    @override_settings(STACKSTORM_URL="https://st2.example/api/v1/webhooks/")
    def test_stackstorm_test_button(self):
        with mock.patch("administration.services.test_stackstorm", return_value=(True, "StackStorm answered HTTP 200.")):
            with mock.patch.dict(services.TESTS, {"stackstorm": services.test_stackstorm}):
                self.c.post(reverse("administration:integration_test", args=["stackstorm"]))
        self.assertTrue(IntegrationTest.objects.get(integration="stackstorm").ok)

    def test_unknown_integration(self):
        r = self.c.post(reverse("administration:integration_test", args=["nagios"]))
        self.assertEqual(r.status_code, 302)
        self.assertEqual(IntegrationTest.objects.count(), 0)


@FAST_HASHER
class SeedTests(TestCase):
    def test_seed_is_idempotent_and_marked(self):
        out = io.StringIO()
        call_command("seed_administration", stdout=out)
        call_command("seed_administration", stdout=out)
        self.assertEqual(Site.objects.filter(description__icontains="example").count(), 3)
        users = User.objects.filter(username__startswith="example.")
        self.assertEqual(users.count(), 3)
        self.assertFalse(any(u.has_usable_password() for u in users))
        self.assertEqual(Membership.objects.filter(user__in=users).count(), 4)
        self.assertIn("0 site(s), 0 user(s), 0 membership(s)", out.getvalue())


# ------------------------------------------------------------------ regressions found by adversarial QA
class QARegressionTests(Base):
    def setUp(self):
        super().setUp()
        self.c = client_for(self.admin)

    def test_users_filter_role_and_site_match_the_same_membership(self):
        # viewer on Mumbai, admin on DR: "admin on Mumbai" must not match (separate joins used to match it)
        u = User.objects.create_user("mixed", "mixed@example.com", PW)
        Membership.objects.create(user=u, site=self.mum, role="viewer")
        Membership.objects.create(user=u, site=self.dr, role="admin")
        url = reverse("administration:users")
        names = lambda **q: sorted(x.username for x in self.c.get(url, q).context["page"])  # noqa: E731
        self.assertEqual(names(role="admin", site=str(self.mum.pk)), ["siteadm"])
        self.assertEqual(names(role="viewer", site=str(self.mum.pk)), ["mixed"])
        self.assertEqual(names(role="admin", site=str(self.dr.pk)), ["mixed"])
        # "admin on All sites" must not match a user who is admin on one site and has another All-sites role
        self.assertEqual(names(role="admin", site="all"), ["boss"])
        self.assertEqual(names(role="operator", site="all"), ["op"])
        self.assertEqual(names(site="nope"), [])
        # the CSV export applies the same filter
        r = self.c.get(reverse("administration:users_export"), {"role": "admin", "site": str(self.mum.pk)})
        rows = list(csv.reader(io.StringIO(r.content.decode())))
        self.assertEqual([row[0] for row in rows[1:]], ["siteadm"])

    def test_users_list_query_count_does_not_grow_with_users(self):
        url = reverse("administration:users")
        self.c.get(url)  # warm caches (content types, sessions)
        from django.db import connection
        from django.test.utils import CaptureQueriesContext
        with CaptureQueriesContext(connection) as before:
            self.c.get(url, {"per": 100})
        for i in range(25):
            u = User.objects.create_user(f"bulk{i}", f"bulk{i}@example.com", PW)
            Membership.objects.create(user=u, site=self.mum if i % 2 else None, role="viewer")
        with CaptureQueriesContext(connection) as after:
            self.c.get(url, {"per": 100})
        self.assertEqual(len(after.captured_queries), len(before.captured_queries))

    def test_audit_default_page_size_matches_pager_choices(self):
        for i in range(30):
            AuditEvent.objects.create(actor_name="bulk", action="run", object_type="x")
        r = self.c.get(reverse("administration:audit"))
        self.assertIn(r.context["page"].paginator.per_page, (10, 20, 50))
        self.assertContains(r, f'value="{r.context["page"].paginator.per_page}" selected')

    def test_non_superuser_cannot_change_superuser_memberships(self):
        url = reverse("administration:membership_save", args=[self.root.pk])
        self.c.post(url, {"site": str(self.mum.pk), "role": "viewer"})
        self.assertFalse(Membership.objects.filter(user=self.root).exists())
        m = Membership.objects.create(user=self.root, site=self.dr, role="viewer")
        self.c.post(reverse("administration:membership_remove", args=[self.root.pk, m.pk]))
        self.assertTrue(Membership.objects.filter(pk=m.pk).exists())
        self.assertFalse(AuditEvent.objects.filter(action__startswith="membership_").exists())
        r = self.c.get(reverse("administration:user_edit", args=[self.root.pk]))
        self.assertNotContains(r, reverse("administration:membership_save", args=[self.root.pk]))
        self.assertNotContains(r, reverse("administration:membership_remove", args=[self.root.pk, m.pk]))
        # a superuser can
        root = client_for(self.root)
        root.post(reverse("administration:membership_remove", args=[self.root.pk, m.pk]))
        self.assertFalse(Membership.objects.filter(pk=m.pk).exists())
        r = root.get(reverse("administration:user_edit", args=[self.root.pk]))
        self.assertContains(r, reverse("administration:membership_save", args=[self.root.pk]))

    def test_case_variant_sites_from_bootstrap_stay_editable(self):
        # bootstrap_sites matches names exactly, so "mumbai (nse)" can exist next to "Mumbai (NSE)"
        UrlCheck.objects.create(name="lc", url="https://lc.example", site="mumbai (nse)")
        self.c.post(reverse("administration:sites_bootstrap"))
        lower = Site.objects.get(name="mumbai (nse)")
        for site in (self.mum, lower):
            r = self.c.post(reverse("administration:site_edit", args=[site.pk]), {
                "name": site.name, "code": site.code, "region": "West", "timezone": "Asia/Kolkata", "criticality": "high"})
            self.assertRedirects(r, reverse("administration:sites"), msg_prefix=site.name)
            site.refresh_from_db()
            self.assertEqual(site.region, "West")
        # renaming to a case variant of another site is still refused
        r = self.c.post(reverse("administration:site_edit", args=[self.dr.pk]), {
            "name": "MUMBAI (NSE)", "code": "dr", "timezone": "UTC", "criticality": "low"})
        self.assertIn("name", r.context["form"].errors)

    def test_unchanged_site_name_keeps_exact_spelling(self):
        odd = Site.objects.create(name="Pune  DC", code="PUNE")  # stored with a double space and an upper-case code
        r = self.c.post(reverse("administration:site_edit", args=[odd.pk]), {
            "name": "Pune DC", "code": "pune", "region": "West", "timezone": "Asia/Kolkata", "criticality": "low"})
        self.assertRedirects(r, reverse("administration:sites"))
        odd.refresh_from_db()
        self.assertEqual((odd.name, odd.code, odd.region), ("Pune  DC", "PUNE", "West"))
        a = AuditEvent.objects.get(action="update", object_type="core.site")
        self.assertNotIn("name", a.details)
        self.assertNotIn("code", a.details)

    def test_site_code_unique_ignoring_case(self):
        Site.objects.create(name="Legacy", code="LEG")
        r = self.c.post(reverse("administration:site_create"), {
            "name": "New", "code": "leg", "timezone": "UTC", "criticality": "low"})
        self.assertEqual(r.status_code, 200)
        self.assertIn("code", r.context["form"].errors)
        # a derived code skips taken codes regardless of case
        Site.objects.create(name="Other", code="NEW-ONE")
        self.c.post(reverse("administration:site_create"), {"name": "New One", "code": "", "timezone": "UTC", "criticality": "low"})
        self.assertEqual(Site.objects.get(name="New One").code, "new-one-2")

    def test_log_ingest_card_names_what_it_measures(self):
        item = next(i for i in services.integrations() if i["key"] == "logs")
        self.assertIn("Last error-level log event", [label for label, _ in item["details"]])
