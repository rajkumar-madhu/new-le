import json
import socket
import threading
import urllib.error
from datetime import date, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import BytesIO, StringIO
from unittest import mock

from django.apps import apps
from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from core import jobs
from core.events import emit
from core.models import AuditEvent, Event, Membership, Site

from . import services
from .models import Execution, Rule, Runbook, Template, parse_steps
from .templatetags.automation_tags import minutes, runbook_steps

ST2 = override_settings(STACKSTORM_URL="https://st2.example.net/api/v1/webhooks/", STACKSTORM_API_KEY="secret-key")
NO_ST2 = override_settings(STACKSTORM_URL="", STACKSTORM_API_KEY="")
LOCAL = override_settings(PROBE_ALLOWED_PRIVATE_CIDRS=["127.0.0.0/8"])
NO_AUTO_INCIDENT = override_settings(INCIDENT_AUTO_CREATE=False, NOTIFY_WEBHOOK_URLS=[], NOTIFY_EMAILS=[])


class FakeResponse:
    def __init__(self, status=202, body=b'{"accepted": true}'):
        self.status = status
        self._body = body

    def read(self, n=-1):
        return self._body if n < 0 else self._body[:n]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def fake_urlopen(status=202, body=b'{"accepted": true}', calls=None):
    def _open(req, timeout=None):
        if calls is not None:
            calls.append((req, timeout))
        return FakeResponse(status, body)
    return _open


class _Hook(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        self.server.received.append((self.path, json.loads(self.rfile.read(n) or b"{}")))
        code = self.server.reply_code
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok": true}')

    def log_message(self, *args):
        pass


class HookServer:
    """A local HTTP server that records webhook POSTs."""

    def __init__(self, code=200):
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), _Hook)
        self.srv.received, self.srv.reply_code = [], code
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}/hook?x=1"
        self.thread = threading.Thread(target=self.srv.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self.srv

    def __exit__(self, *exc):
        self.srv.shutdown()
        self.srv.server_close()


def users():
    viewer = User.objects.create_user("viewer", password="x")
    operator = User.objects.create_user("operator", password="x", is_staff=True)
    admin = User.objects.create_superuser("admin", password="x")
    return viewer, operator, admin


def make_rule(**kw):
    defaults = {"name": "Rule", "enabled": True, "match_source": "urlchecker", "min_severity": "warning",
                "cooldown_minutes": 15, "action": "stackstorm", "action_params": {"trigger": "restart"}}
    defaults.update(kw)
    return Rule.objects.create(**defaults)


def make_runbook(**kw):
    defaults = {"title": "Portal down", "service": "Portal", "steps": "1. Check\n2. Fix"}
    defaults.update(kw)
    return Runbook.objects.create(**defaults)


# ------------------------------------------------------------------ models
class StepParsingTests(TestCase):
    def test_numbered_steps_with_continuation_lines(self):
        steps = parse_steps("1. Check the pool\n   $ curl -s x\n2) Restart\n- Escalate")
        self.assertEqual(steps, [["Check the pool", "   $ curl -s x"], ["Restart"], ["Escalate"]])

    def test_unnumbered_lines_become_steps(self):
        self.assertEqual(parse_steps("Check\nRestart\n  \n"), [["Check"], ["Restart"]])

    def test_paragraphs_become_steps(self):
        self.assertEqual(parse_steps("Check the pool\nand the nodes\n\nRestart"), [["Check the pool", "and the nodes"], ["Restart"]])

    def test_preamble_before_first_number(self):
        self.assertEqual(parse_steps("Before you start:\n1. One\n2. Two"), [["Before you start:"], ["One"], ["Two"]])

    def test_empty(self):
        self.assertEqual(parse_steps(""), [])

    def test_rendering_escapes_html(self):
        html = str(runbook_steps("1. <script>alert(1)</script> & go\n   $ rm -rf <dir>\n2. Done"))
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt; &amp; go", html)
        self.assertIn('<code class="cmd">$ rm -rf &lt;dir&gt;</code>', html)
        self.assertEqual(html.count("<li>"), 2)
        self.assertTrue(html.startswith('<ol class="rb-steps">'))

    def test_minutes_filter(self):
        self.assertEqual([minutes(0), minutes(15), minutes(120), minutes(1440), minutes(2880)],
                         ["None", "15 min", "2 h", "1 day", "2 days"])


class RunbookModelTests(TestCase):
    def test_review_due(self):
        rb = make_runbook()
        self.assertTrue(rb.review_due)
        rb.last_reviewed = timezone.localdate()
        self.assertFalse(rb.review_due)
        rb.last_reviewed = timezone.localdate() - timedelta(days=200)
        self.assertTrue(rb.review_due)

    def test_tags_and_example(self):
        rb = make_runbook(tags="example, web , ")
        self.assertEqual(rb.tag_list, ["example", "web"])
        self.assertTrue(rb.is_example)


class RuleMatchingTests(TestCase):
    def ev(self, **kw):
        d = {"source": "urlchecker", "severity": "critical", "title": "Portal is Down", "site": "Mumbai"}
        d.update(kw)
        return Event(**d)

    def test_source_list_and_severity(self):
        r = make_rule(match_source="urlchecker, TCPcheck", min_severity="warning")
        self.assertTrue(r.matches(self.ev()))
        self.assertTrue(r.matches(self.ev(source="tcpcheck", severity="warning")))
        self.assertFalse(r.matches(self.ev(source="network")))
        self.assertFalse(r.matches(self.ev(severity="info")))
        self.assertFalse(r.matches(self.ev(severity="ok")))

    def test_any_source_and_ok(self):
        r = make_rule(match_source="", min_severity="ok")
        self.assertTrue(r.matches(self.ev(source="anything", severity="ok")))

    def test_title_and_site(self):
        r = make_rule(title_contains="DOWN", site="Mumbai")
        self.assertTrue(r.matches(self.ev()))
        self.assertFalse(r.matches(self.ev(title="Portal recovered")))
        self.assertFalse(r.matches(self.ev(site="Delhi")))
        explained = dict((c, ok) for c, ok, _d in r.explain(self.ev(site="Delhi")))
        self.assertEqual(explained, {"Source": True, "Severity": True, "Title": True, "Site": False})

    def test_all_sites_rule_matches_any_site(self):
        self.assertTrue(make_rule(site="All Sites").matches(self.ev(site="Delhi")))

    def test_summaries(self):
        rb = make_runbook()
        self.assertEqual(make_rule(name="a").action_summary(), "StackStorm: restart")
        self.assertEqual(make_rule(name="b", action="open_incident", action_params={"priority": "P1"}).action_summary(), "Open P1 incident")
        self.assertEqual(make_rule(name="c", action="link_runbook", runbook=rb).action_summary(), "Runbook: Portal down")
        self.assertIn("urlchecker", make_rule(name="d").match_summary())


# ------------------------------------------------------------------ StackStorm
class StackStormTests(TestCase):
    @NO_ST2
    def test_not_configured_records_failed_execution(self):
        with mock.patch("automation.services.urllib.request.urlopen") as op:
            ex = services.trigger_stackstorm("restart", {"a": 1})
        op.assert_not_called()
        self.assertEqual(ex.status, "failed")
        self.assertIn("not configured", ex.error)
        self.assertEqual(Execution.objects.get().kind, "stackstorm")
        self.assertIsNotNone(ex.finished_at)

    @ST2
    def test_success_posts_json_with_api_key_and_timeout(self):
        calls = []
        with mock.patch("automation.services.urllib.request.urlopen", side_effect=fake_urlopen(calls=calls)):
            ex = services.trigger_stackstorm("linkedeye/restart", {"host": "web-1"}, triggered_by="alice")
        self.assertEqual(ex.status, "success")
        self.assertEqual(ex.http_status, 202)
        self.assertIn("accepted", ex.response_excerpt)
        req, timeout = calls[0]
        self.assertEqual(timeout, 10)
        self.assertEqual(req.full_url, "https://st2.example.net/api/v1/webhooks/linkedeye/restart")
        self.assertEqual(req.get_method(), "POST")
        self.assertEqual(req.get_header("St2-api-key"), "secret-key")
        self.assertEqual(json.loads(req.data), {"host": "web-1"})
        self.assertEqual(ex.triggered_by, "alice")

    @ST2
    def test_http_error_is_recorded(self):
        err = urllib.error.HTTPError("u", 401, "Unauthorized", {}, BytesIO(b'{"faultstring": "bad key"}'))
        with mock.patch("automation.services.urllib.request.urlopen", side_effect=err):
            ex = services.trigger_stackstorm("restart", {})
        self.assertEqual((ex.status, ex.http_status), ("failed", 401))
        self.assertIn("bad key", ex.response_excerpt)

    @ST2
    def test_unreachable_and_unexpected_errors_never_raise(self):
        with mock.patch("automation.services.urllib.request.urlopen", side_effect=urllib.error.URLError("refused")):
            ex = services.trigger_stackstorm("restart", {})
        self.assertIn("unreachable", ex.error)
        with mock.patch("automation.services.urllib.request.urlopen", side_effect=RuntimeError("boom")):
            ex = services.trigger_stackstorm("restart", {})
        self.assertEqual(ex.status, "failed")
        self.assertIn("RuntimeError", ex.error)

    @ST2
    def test_invalid_trigger_is_refused_without_a_call(self):
        with mock.patch("automation.services.urllib.request.urlopen") as op:
            ex = services.trigger_stackstorm("../../admin", {})
        op.assert_not_called()
        self.assertIn("Invalid trigger", ex.error)

    @ST2
    def test_non_json_payload_is_stored(self):
        with mock.patch("automation.services.urllib.request.urlopen", side_effect=fake_urlopen()):
            ex = services.trigger_stackstorm("restart", {"when": timezone.now()})
        self.assertIsInstance(ex.payload["when"], str)

    @ST2
    def test_connection_test(self):
        with mock.patch("automation.services.urllib.request.urlopen", side_effect=fake_urlopen(status=200)):
            self.assertTrue(services.test_stackstorm()[0])
        err = urllib.error.HTTPError("u", 403, "Forbidden", {}, BytesIO(b""))
        with mock.patch("automation.services.urllib.request.urlopen", side_effect=err):
            ok, text = services.test_stackstorm()
        self.assertFalse(ok)
        self.assertIn("API key", text)

    def test_display_url_hides_credentials(self):
        with override_settings(STACKSTORM_URL="https://u:p@st2.local:8443/api/v1/webhooks/?token=x"):
            self.assertEqual(services.stackstorm_display_url(), "https://st2.local:8443/api/v1/webhooks/")


# ------------------------------------------------------------------ webhooks
class WebhookTests(TestCase):
    def test_metadata_and_private_addresses_are_refused(self):
        for url in ("http://169.254.169.254/latest/meta-data", "http://127.0.0.1:9/x", "ftp://example.com/x",
                    "http://user:pw@example.com/"):
            with self.subTest(url=url):
                with self.assertRaises(services.WebhookError):
                    services.check_webhook_url(url)
        ex = services.post_webhook("http://169.254.169.254/latest", {"a": 1})
        self.assertEqual(ex.status, "failed")
        self.assertIn("refused", ex.error)

    def test_unresolvable_host(self):
        with mock.patch("probes.checks.socket.getaddrinfo", side_effect=socket.gaierror("no such host")):
            with self.assertRaises(services.WebhookError):
                services.check_webhook_url("https://nope.invalid/hook")

    @LOCAL
    def test_post_to_allowed_local_server(self):
        with HookServer() as srv:
            ex = services.post_webhook(f"http://127.0.0.1:{srv.server_address[1]}/hook?x=1", {"hello": "world"})
        self.assertEqual((ex.status, ex.http_status), ("success", 200))
        self.assertEqual(srv.received, [("/hook?x=1", {"hello": "world"})])
        self.assertIn('"ok"', ex.response_excerpt)

    @LOCAL
    def test_error_status_is_failed(self):
        with HookServer(code=500) as srv:
            ex = services.post_webhook(f"http://127.0.0.1:{srv.server_address[1]}/", {})
        self.assertEqual((ex.status, ex.http_status), ("failed", 500))


# ------------------------------------------------------------------ rule engine (event listener)
@NO_AUTO_INCIDENT
class RuleEngineTests(TestCase):
    def setUp(self):
        self.calls = []
        p = mock.patch("automation.services.urllib.request.urlopen", side_effect=fake_urlopen(calls=self.calls))
        p.start()
        self.addCleanup(p.stop)

    @ST2
    def test_matching_event_triggers_stackstorm_and_emits_info_event(self):
        rule = make_rule(action_params={"trigger": "restart", "payload": {"team": "noc"}})
        ev = emit(source="urlchecker", title="Portal is Down", severity="critical", site="Mumbai", fingerprint="url:1")
        ex = Execution.objects.get()
        self.assertEqual((ex.kind, ex.status, ex.rule, ex.event_id, ex.fingerprint, ex.site),
                         ("stackstorm", "success", rule, ev.pk, "url:1", "Mumbai"))
        body = json.loads(self.calls[0][0].data)
        self.assertEqual(body["event"]["title"], "Portal is Down")
        self.assertEqual(body["rule"]["name"], "Rule")
        self.assertEqual(body["team"], "noc")
        rule.refresh_from_db()
        self.assertEqual(rule.fire_count, 1)
        self.assertIsNotNone(rule.last_fired_at)
        info = Event.objects.get(source="automation")
        self.assertEqual(info.severity, "info")
        self.assertIn("fired", info.title)

    @ST2
    def test_non_matching_disabled_and_automation_events_are_ignored(self):
        make_rule()
        make_rule(name="off", enabled=False, match_source="")
        emit(source="urlchecker", title="slow", severity="info", fingerprint="url:1")
        emit(source="tcpcheck", title="down", severity="critical", fingerprint="tcp:1")
        emit(source="automation", title="something", severity="critical", fingerprint="url:1")
        self.assertEqual(Execution.objects.count(), 0)

    @ST2
    def test_cooldown_per_rule_and_fingerprint(self):
        rule = make_rule(cooldown_minutes=15)
        emit(source="urlchecker", title="down", severity="critical", fingerprint="url:1")
        emit(source="urlchecker", title="down again", severity="critical", fingerprint="url:1")
        self.assertEqual(Execution.objects.count(), 1)
        emit(source="urlchecker", title="other down", severity="critical", fingerprint="url:2")
        self.assertEqual(Execution.objects.count(), 2)
        Execution.objects.update(started_at=timezone.now() - timedelta(minutes=16))
        emit(source="urlchecker", title="down later", severity="critical", fingerprint="url:1")
        self.assertEqual(Execution.objects.count(), 3)
        rule.cooldown_minutes = 0
        rule.save()
        emit(source="urlchecker", title="down", severity="critical", fingerprint="url:1")
        emit(source="urlchecker", title="down", severity="critical", fingerprint="url:1")
        self.assertEqual(Execution.objects.count(), 5)

    @NO_ST2
    def test_stackstorm_not_configured_rule_records_failure(self):
        make_rule()
        emit(source="urlchecker", title="down", severity="critical", fingerprint="url:1")
        ex = Execution.objects.get()
        self.assertEqual(ex.status, "failed")
        self.assertIn("not configured", ex.error)
        self.assertIn("failed", Event.objects.get(source="automation").title)

    def test_open_incident_action_dedupes_and_does_not_loop(self):
        self.assertTrue(apps.is_installed("servicedesk"))
        Ticket = apps.get_model("servicedesk", "Ticket")
        rb = make_runbook()
        rule = make_rule(match_source="", min_severity="info", cooldown_minutes=0, action="open_incident",
                         action_params={"priority": "P2"}, runbook=rb)
        emit(source="tcpcheck", title="Gateway down", severity="critical", site="Mumbai", fingerprint="tcp:9", host="gw-1")
        t = Ticket.objects.get()
        self.assertEqual((t.priority, t.fingerprint, t.source, t.site, t.ci_name), ("P2", "tcp:9", "automation", "Mumbai", "gw-1"))
        self.assertIn("Portal down", t.description)
        ex = Execution.objects.get()
        self.assertEqual((ex.kind, ex.status, ex.result_label), ("rule", "success", t.number))
        self.assertEqual(ex.result_url, t.get_absolute_url())
        # the incident's own "opened" event did not re-enter the rules (no second incident, one execution)
        emit(source="tcpcheck", title="Gateway down", severity="critical", site="Mumbai", fingerprint="tcp:9")
        self.assertEqual(Ticket.objects.count(), 1)
        self.assertEqual(Execution.objects.filter(rule=rule).count(), 2)

    def test_open_incident_guarded_when_servicedesk_missing(self):
        make_rule(action="open_incident", action_params={})
        real = apps.is_installed
        with mock.patch("django.apps.apps.is_installed", side_effect=lambda n: False if n == "servicedesk" else real(n)):
            emit(source="urlchecker", title="down", severity="critical", fingerprint="x")
        ex = Execution.objects.get()
        self.assertEqual(ex.status, "failed")
        self.assertIn("not installed", ex.error)

    def test_link_runbook_action(self):
        rb = make_runbook()
        make_rule(action="link_runbook", action_params={}, runbook=rb)
        emit(source="urlchecker", title="down", severity="warning", fingerprint="x")
        ex = Execution.objects.get()
        self.assertEqual((ex.status, ex.result_label, ex.result_url), ("success", rb.title, rb.get_absolute_url()))

    def test_link_runbook_missing(self):
        make_rule(action="link_runbook", action_params={}, runbook=None)
        emit(source="urlchecker", title="down", severity="warning", fingerprint="x")
        self.assertIn("no longer exists", Execution.objects.get().error)

    @LOCAL
    def test_webhook_action(self):
        with HookServer() as srv:
            make_rule(action="webhook", action_params={"url": f"http://127.0.0.1:{srv.server_address[1]}/in"})
            emit(source="urlchecker", title="down", severity="critical", fingerprint="x")
        ex = Execution.objects.get()
        self.assertEqual((ex.kind, ex.status), ("webhook", "success"))
        self.assertEqual(srv.received[0][1]["event"]["title"], "down")

    def test_listener_never_raises(self):
        make_rule()
        with mock.patch("automation.services.fire", side_effect=RuntimeError("boom")):
            ev = emit(source="urlchecker", title="down", severity="critical", fingerprint="x")
        self.assertIsNotNone(ev.pk)
        with mock.patch("automation.services.Rule.objects.filter", side_effect=RuntimeError("db gone")):
            ev = emit(source="urlchecker", title="down", severity="critical", fingerprint="y")
        self.assertIsNotNone(ev.pk)


class HousekeepingTests(TestCase):
    def test_job_registered(self):
        self.assertIn("automation.housekeeping", jobs.JOBS)

    def test_stale_pending_failed_and_old_pruned(self):
        now = timezone.now()
        stale = Execution.objects.create(kind="stackstorm", trigger="t", status="pending", started_at=now - timedelta(hours=1))
        fresh = Execution.objects.create(kind="stackstorm", trigger="t", status="pending", started_at=now)
        Execution.objects.create(kind="stackstorm", trigger="old", status="success", started_at=now - timedelta(days=400))
        self.assertEqual(services.housekeeping(now), "1 stale, 1 pruned")
        stale.refresh_from_db()
        fresh.refresh_from_db()
        self.assertEqual((stale.status, fresh.status), ("failed", "pending"))
        self.assertFalse(Execution.objects.filter(trigger="old").exists())


# ------------------------------------------------------------------ templates (service)
@NO_AUTO_INCIDENT
class TemplateApplyServiceTests(TestCase):
    def test_url_check(self):
        t = Template.objects.create(kind="url_check", name="Health")
        obj, url, label = services.apply_template(t, {"name": "Portal", "url": "https://portal.example.com/health",
                                                      "interval_seconds": 60, "site": "All Sites"})
        UrlCheck = apps.get_model("urlchecker", "UrlCheck")
        self.assertEqual(UrlCheck.objects.get().name, "Portal")
        self.assertEqual(url, reverse("urlchecker:detail", args=[obj.pk]))
        with self.assertRaises(services.ApplyError):
            services.apply_template(t, {"name": "Portal", "url": "https://portal.example.com/health", "site": "All Sites"})

    def test_tcp_check_validation_errors(self):
        t = Template.objects.create(kind="tcp_check", name="SSH")
        with self.assertRaises(services.ApplyError) as cm:
            services.apply_template(t, {"name": "SSH", "host": "h", "port": 70000, "site": "All Sites"})
        self.assertIn("port", cm.exception.errors)
        obj, url, label = services.apply_template(t, {"name": "SSH", "host": "h.example.com", "port": 22, "site": "All Sites"})
        self.assertEqual(obj.port, 22)
        self.assertTrue(url)

    def test_incident_and_notification(self):
        t = Template.objects.create(kind="incident", name="Overrun")
        ticket, url, label = services.apply_template(t, {"title": "Overran", "priority": "P2"})
        self.assertEqual((ticket.kind, ticket.priority, ticket.source), ("incident", "P2", "automation"))
        n = Template.objects.create(kind="notification", name="Notice")
        ev, url, label = services.apply_template(n, {"title": "SOD failed", "severity": "warning", "message": "m"})
        self.assertEqual((ev.source, ev.severity, ev.kind), ("automation", "warning", "notification"))

    def test_missing_module_is_reported(self):
        t = Template.objects.create(kind="url_check", name="Health")
        with mock.patch("django.apps.apps.get_model", side_effect=LookupError):
            with self.assertRaises(services.ApplyError) as cm:
                services.apply_template(t, {"name": "x", "url": "https://x.example.com"})
        self.assertIn("not installed", cm.exception.errors["__all__"])


# ------------------------------------------------------------------ views
class ViewTestBase(TestCase):
    def setUp(self):
        self.viewer, self.operator, self.admin = users()
        self.c = Client()

    def login(self, user):
        self.c.force_login(user)
        return self.c


class PageRenderTests(ViewTestBase):
    def setUp(self):
        super().setUp()
        self.rb = make_runbook(steps="1. <b>bold</b> step\n2. second", symptoms="Users see <i>errors</i>")
        self.rule = make_rule(runbook=self.rb)
        self.tpl = Template.objects.create(kind="url_check", name="Health", fields={"interval_seconds": 60})
        self.ex = Execution.objects.create(kind="stackstorm", trigger="restart", status="failed", error="nope",
                                           payload={"a": "<x>"}, rule=self.rule)

    def test_anonymous_is_redirected(self):
        r = Client().get(reverse("automation:runbooks"))
        self.assertEqual(r.status_code, 302)

    def test_viewer_can_read_every_page(self):
        self.login(self.viewer)
        urls = [reverse("automation:runbooks"), reverse("automation:runbook_detail", args=[self.rb.pk]),
                reverse("automation:stackstorm"), reverse("automation:workflows"),
                reverse("automation:rule_detail", args=[self.rule.pk]), reverse("automation:templates"),
                reverse("automation:template_detail", args=[self.tpl.pk]),
                reverse("automation:execution_detail", args=[self.ex.pk]),
                reverse("automation:workflows") + "?status=failed&kind=stackstorm&rule=%d" % self.rule.pk,
                reverse("automation:runbooks") + "?q=portal&review=due", reverse("automation:templates") + "?kind=url_check"]
        for u in urls:
            with self.subTest(url=u):
                r = self.c.get(u)
                self.assertEqual(r.status_code, 200)
                self.assertNotContains(r, "New runbook")

    def test_url_names(self):
        self.assertEqual(reverse("automation:runbooks"), "/automation/runbooks/")
        self.assertEqual(reverse("automation:stackstorm"), "/automation/stackstorm/")
        self.assertEqual(reverse("automation:workflows"), "/automation/workflows/")
        self.assertEqual(reverse("automation:templates"), "/templates/")

    def test_runbook_detail_escapes_and_numbers_steps(self):
        r = self.login(self.viewer).get(reverse("automation:runbook_detail", args=[self.rb.pk]))
        self.assertContains(r, "&lt;b&gt;bold&lt;/b&gt; step")
        self.assertContains(r, "Users see &lt;i&gt;errors&lt;/i&gt;")
        self.assertNotContains(r, "<b>bold</b>")
        self.assertContains(r, '<ol class="rb-steps">')

    def test_execution_payload_escaped(self):
        r = self.login(self.viewer).get(reverse("automation:execution_detail", args=[self.ex.pk]))
        self.assertContains(r, "&lt;x&gt;")

    @NO_ST2
    def test_stackstorm_not_connected_state(self):
        r = self.login(self.operator).get(reverse("automation:stackstorm"))
        self.assertContains(r, "StackStorm is not connected")
        self.assertContains(r, "LINKEDEYE_STACKSTORM_URL")

    @ST2
    def test_stackstorm_configured_state(self):
        r = self.login(self.operator).get(reverse("automation:stackstorm"))
        self.assertNotContains(r, "StackStorm is not connected")
        self.assertContains(r, "https://st2.example.net/api/v1/webhooks/")
        self.assertNotContains(r, "secret-key")

    def test_operator_sees_forms_viewer_gets_403(self):
        forms = [reverse("automation:runbook_create"), reverse("automation:runbook_edit", args=[self.rb.pk]),
                 reverse("automation:rule_create"), reverse("automation:rule_edit", args=[self.rule.pk]),
                 reverse("automation:template_create"), reverse("automation:template_create") + "?kind=incident",
                 reverse("automation:template_edit", args=[self.tpl.pk]), reverse("automation:template_apply", args=[self.tpl.pk])]
        self.login(self.viewer)
        for u in forms:
            with self.subTest(viewer=u):
                self.assertEqual(self.c.get(u).status_code, 403)
        self.login(self.operator)
        for u in forms:
            with self.subTest(operator=u):
                self.assertEqual(self.c.get(u).status_code, 200)

    def test_csv_exports(self):
        self.login(self.viewer)
        r = self.c.get(reverse("automation:runbook_export"))
        self.assertEqual(r["Content-Type"], "text/csv")
        self.assertIn("Portal down", r.content.decode())
        r = self.c.get(reverse("automation:execution_export") + "?status=failed")
        self.assertIn("restart", r.content.decode())


class RunbookMutationTests(ViewTestBase):
    def data(self, **kw):
        d = {"title": "DB failover", "service": "Core DB", "ci_name": "db-01", "site": "All Sites", "owner": "DBA",
             "tags": "db, db, p1", "last_reviewed": "", "symptoms": "Replication lag", "steps": "1. Check lag\n2. Fail over"}
        d.update(kw)
        return d

    def test_csrf_enforced(self):
        c = Client(enforce_csrf_checks=True)
        c.force_login(self.admin)
        r = c.post(reverse("automation:runbook_create"), self.data())
        self.assertEqual(r.status_code, 403)
        self.assertFalse(Runbook.objects.exists())

    def test_viewer_cannot_create(self):
        r = self.login(self.viewer).post(reverse("automation:runbook_create"), self.data())
        self.assertEqual(r.status_code, 302)
        self.assertFalse(Runbook.objects.exists())

    def test_operator_creates_edits_reviews(self):
        self.login(self.operator)
        r = self.c.post(reverse("automation:runbook_create"), self.data())
        rb = Runbook.objects.get()
        self.assertRedirects(r, rb.get_absolute_url())
        self.assertEqual((rb.tags, rb.created_by), ("db, p1", "operator"))
        self.assertTrue(AuditEvent.objects.filter(action="create", object_type="automation.runbook", object_id=str(rb.pk)).exists())
        r = self.c.post(reverse("automation:runbook_edit", args=[rb.pk]), self.data(owner="Platform"), follow=True)
        self.assertContains(r, "Saved runbook")
        rb.refresh_from_db()
        self.assertEqual(rb.owner, "Platform")
        self.assertTrue(AuditEvent.objects.filter(action="update", object_id=str(rb.pk)).exists())
        self.c.post(reverse("automation:runbook_reviewed", args=[rb.pk]))
        rb.refresh_from_db()
        self.assertEqual(rb.last_reviewed, timezone.localdate())
        self.assertTrue(AuditEvent.objects.filter(action="review").exists())

    def test_duplicate_title_and_empty_steps_rejected(self):
        make_runbook(title="DB failover")
        r = self.login(self.operator).post(reverse("automation:runbook_create"), self.data(steps="  "))
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "already exists")
        self.assertContains(r, "Add at least one step")
        self.assertEqual(Runbook.objects.count(), 1)

    def test_delete_is_admin_only(self):
        rb = make_runbook()
        self.login(self.operator).post(reverse("automation:runbook_delete", args=[rb.pk]))
        self.assertTrue(Runbook.objects.filter(pk=rb.pk).exists())
        r = self.login(self.admin).post(reverse("automation:runbook_delete", args=[rb.pk]))
        self.assertRedirects(r, reverse("automation:runbooks"))
        self.assertFalse(Runbook.objects.filter(pk=rb.pk).exists())
        self.assertTrue(AuditEvent.objects.filter(action="delete", object_type="automation.runbook").exists())

    def test_get_on_mutation_endpoints_not_allowed(self):
        rb = make_runbook()
        self.login(self.admin)
        self.assertEqual(self.c.get(reverse("automation:runbook_delete", args=[rb.pk])).status_code, 405)
        self.assertEqual(self.c.get(reverse("automation:runbook_reviewed", args=[rb.pk])).status_code, 405)


class SiteScopeTests(ViewTestBase):
    def setUp(self):
        super().setUp()
        self.mumbai = Site.objects.create(name="Mumbai", code="mumbai")
        Site.objects.create(name="Delhi", code="delhi")
        self.local_op = User.objects.create_user("local", password="x")
        Membership.objects.create(user=self.local_op, site=self.mumbai, role="operator")

    def test_site_operator_scope(self):
        mine = make_runbook(title="Mumbai book", site="Mumbai")
        other = make_runbook(title="Delhi book", site="Delhi")
        glob = make_runbook(title="Global book", site="All Sites")
        self.login(self.local_op)
        r = self.c.get(reverse("automation:runbooks"))
        self.assertContains(r, "Mumbai book")
        self.assertContains(r, "Global book")
        self.assertNotContains(r, "Delhi book")
        self.assertEqual(self.c.get(reverse("automation:runbook_detail", args=[other.pk])).status_code, 404)
        # may edit Mumbai records, not global ones
        data = {"title": "Mumbai book", "site": "Mumbai", "steps": "1. a"}
        r = self.c.post(reverse("automation:runbook_edit", args=[mine.pk]), data)
        self.assertEqual(r.status_code, 302)
        r = self.c.post(reverse("automation:runbook_create"), {"title": "New global", "site": "All Sites", "steps": "1. a"})
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "You cannot add or change runbooks")
        r = self.c.post(reverse("automation:runbook_reviewed", args=[glob.pk]))
        glob.refresh_from_db()
        self.assertIsNone(glob.last_reviewed)


@NO_AUTO_INCIDENT
class StackStormViewTests(ViewTestBase):
    @ST2
    def test_operator_manual_trigger(self):
        calls = []
        with mock.patch("automation.services.urllib.request.urlopen", side_effect=fake_urlopen(calls=calls)):
            r = self.login(self.operator).post(reverse("automation:stackstorm_trigger"),
                                               {"trigger": "restart_web", "payload": '{"host": "web-1"}'}, follow=True)
        ex = Execution.objects.get()
        self.assertEqual((ex.status, ex.trigger, ex.payload, ex.triggered_by), ("success", "restart_web", {"host": "web-1"}, "operator"))
        self.assertContains(r, "Triggered")
        self.assertTrue(AuditEvent.objects.filter(action="run", object_type="automation.execution").exists())
        self.assertTrue(Event.objects.filter(source="automation", title__contains="restart_web").exists())

    @ST2
    def test_invalid_payload_shows_error(self):
        with mock.patch("automation.services.urllib.request.urlopen") as op:
            r = self.login(self.operator).post(reverse("automation:stackstorm_trigger"), {"trigger": "x", "payload": "[1, 2]"})
        op.assert_not_called()
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "must be a JSON object")
        self.assertFalse(Execution.objects.exists())

    @ST2
    def test_viewer_cannot_trigger(self):
        with mock.patch("automation.services.urllib.request.urlopen") as op:
            self.login(self.viewer).post(reverse("automation:stackstorm_trigger"), {"trigger": "x", "payload": "{}"})
        op.assert_not_called()
        self.assertFalse(Execution.objects.exists())

    @ST2
    def test_connection_test_is_audited(self):
        with mock.patch("automation.services.urllib.request.urlopen", side_effect=fake_urlopen(status=200)):
            r = self.login(self.operator).post(reverse("automation:stackstorm_test"), follow=True)
        self.assertContains(r, "StackStorm answered HTTP 200")
        self.assertTrue(AuditEvent.objects.filter(action="test_connection").exists())

    @ST2
    def test_rerun(self):
        ex = Execution.objects.create(kind="stackstorm", trigger="restart", payload={"a": 1}, status="failed")
        with mock.patch("automation.services.urllib.request.urlopen", side_effect=fake_urlopen()):
            self.login(self.viewer).post(reverse("automation:execution_rerun", args=[ex.pk]))
            self.assertEqual(Execution.objects.count(), 1)
            r = self.login(self.operator).post(reverse("automation:execution_rerun", args=[ex.pk]))
        new = Execution.objects.exclude(pk=ex.pk).get()
        self.assertRedirects(r, new.get_absolute_url())
        self.assertEqual((new.payload, new.status), ({"a": 1}, "success"))


@NO_AUTO_INCIDENT
class RuleViewTests(ViewTestBase):
    def rule_data(self, **kw):
        d = {"name": "Restart web", "description": "", "enabled": "on", "match_source": "URLChecker, tcpcheck",
             "min_severity": "critical", "title_contains": "", "site": "", "cooldown_minutes": "10", "action": "stackstorm",
             "trigger": "restart_web", "payload": '{"team": "noc"}', "priority": "P3", "incident_title": "", "webhook_url": "",
             "runbook": ""}
        d.update(kw)
        return d

    def test_create_stackstorm_rule(self):
        r = self.login(self.operator).post(reverse("automation:rule_create"), self.rule_data())
        rule = Rule.objects.get()
        self.assertRedirects(r, rule.get_absolute_url())
        self.assertEqual(rule.match_source, "urlchecker, tcpcheck")
        self.assertEqual(rule.action_params, {"trigger": "restart_web", "payload": {"team": "noc"}})
        self.assertTrue(rule.enabled)
        self.assertTrue(AuditEvent.objects.filter(action="create", object_type="automation.rule").exists())

    def test_action_specific_validation(self):
        self.login(self.operator)
        r = self.c.post(reverse("automation:rule_create"), self.rule_data(trigger=""))
        self.assertContains(r, "Enter the StackStorm trigger")
        r = self.c.post(reverse("automation:rule_create"), self.rule_data(action="webhook", webhook_url="http://169.254.169.254/x"))
        self.assertContains(r, "refused by the probe policy")
        r = self.c.post(reverse("automation:rule_create"), self.rule_data(action="link_runbook"))
        self.assertContains(r, "Choose the runbook")
        r = self.c.post(reverse("automation:rule_create"), self.rule_data(payload="not json"))
        self.assertContains(r, "not valid JSON")
        self.assertFalse(Rule.objects.exists())

    @LOCAL
    def test_webhook_rule_allowed_target(self):
        self.login(self.operator).post(reverse("automation:rule_create"),
                                       self.rule_data(action="webhook", webhook_url="http://127.0.0.1:8080/hook", payload=""))
        self.assertEqual(Rule.objects.get().action_params, {"url": "http://127.0.0.1:8080/hook"})

    def test_open_incident_rule_params(self):
        self.login(self.operator).post(reverse("automation:rule_create"),
                                       self.rule_data(action="open_incident", priority="P1", incident_title="Gateway down"))
        self.assertEqual(Rule.objects.get().action_params, {"priority": "P1", "title": "Gateway down"})

    def test_toggle_and_delete(self):
        rule = make_rule(enabled=False)
        self.login(self.viewer).post(reverse("automation:rule_toggle", args=[rule.pk]))
        rule.refresh_from_db()
        self.assertFalse(rule.enabled)
        r = self.login(self.operator).post(reverse("automation:rule_toggle", args=[rule.pk]), {"next": "list"})
        self.assertRedirects(r, reverse("automation:workflows"))
        rule.refresh_from_db()
        self.assertTrue(rule.enabled)
        self.assertTrue(AuditEvent.objects.filter(action="enable", object_id=str(rule.pk)).exists())
        self.c.post(reverse("automation:rule_delete", args=[rule.pk]))
        self.assertTrue(Rule.objects.filter(pk=rule.pk).exists())
        self.login(self.admin).post(reverse("automation:rule_delete", args=[rule.pk]))
        self.assertFalse(Rule.objects.filter(pk=rule.pk).exists())
        self.assertTrue(AuditEvent.objects.filter(action="delete", object_type="automation.rule").exists())

    def test_test_evaluation_has_no_side_effects(self):
        rule = make_rule(title_contains="down")
        data = {"source": "urlchecker", "severity": "critical", "title": "Portal is DOWN", "site": "", "fingerprint": "f"}
        with mock.patch("automation.services.urllib.request.urlopen") as op:
            r = self.login(self.viewer).post(reverse("automation:rule_test", args=[rule.pk]), data)
        op.assert_not_called()
        self.assertContains(r, "The event matches this rule")
        self.assertFalse(Execution.objects.exists())
        r = self.c.post(reverse("automation:rule_test", args=[rule.pk]), dict(data, title="Portal recovered"))
        self.assertContains(r, "The event does not match")

    @ST2
    def test_test_run_executes_action(self):
        rule = make_rule()
        data = {"source": "urlchecker", "severity": "critical", "title": "down", "fingerprint": "f", "run": "on"}
        with mock.patch("automation.services.urllib.request.urlopen", side_effect=fake_urlopen()):
            self.login(self.viewer).post(reverse("automation:rule_test", args=[rule.pk]), data)
            self.assertFalse(Execution.objects.exists())
            r = self.login(self.operator).post(reverse("automation:rule_test", args=[rule.pk]), data)
        self.assertEqual(r.status_code, 302)
        ex = Execution.objects.get()
        self.assertEqual((ex.rule, ex.status, ex.triggered_by), (rule, "success", "operator (test)"))
        self.assertTrue(AuditEvent.objects.filter(action="run", object_type="automation.rule").exists())

    def test_sample_event_prefill(self):
        rule = make_rule()
        ev = Event.objects.create(source="urlchecker", title="Prefilled title", severity="critical")
        r = self.login(self.viewer).get(reverse("automation:rule_detail", args=[rule.pk]) + f"?event={ev.pk}")
        self.assertContains(r, 'value="Prefilled title"')


@NO_AUTO_INCIDENT
class TemplateViewTests(ViewTestBase):
    def test_create_template_stores_only_given_values(self):
        r = self.login(self.operator).post(reverse("automation:template_create") + "?kind=tcp_check",
                                           {"kind": "tcp_check", "name": "SSH template", "description": "ssh", "v_port": "22",
                                            "v_interval_seconds": "300", "v_site": "", "v_host": "", "v_name": "",
                                            "v_expect_banner": "SSH-"})
        t = Template.objects.get()
        self.assertRedirects(r, t.get_absolute_url())
        self.assertEqual((t.kind, t.fields), ("tcp_check", {"port": 22, "interval_seconds": 300, "expect_banner": "SSH-"}))
        self.assertTrue(AuditEvent.objects.filter(action="create", object_type="automation.template").exists())

    def test_template_kind_chooser(self):
        r = self.login(self.operator).get(reverse("automation:template_create"))
        self.assertContains(r, "?kind=url_check")

    def test_apply_url_check(self):
        t = Template.objects.create(kind="url_check", name="Health", fields={"interval_seconds": 60, "check_type": "api"})
        self.login(self.operator)
        r = self.c.get(reverse("automation:template_apply", args=[t.pk]))
        self.assertContains(r, "Nothing is created until you confirm")
        UrlCheck = apps.get_model("urlchecker", "UrlCheck")
        data = {"name": "Portal health", "url": "https://portal.example.com/health", "check_type": "api", "method": "GET",
                "expected_status": "200", "interval_seconds": "60", "timeout_seconds": "10", "degraded_ms": "1000",
                "site": "All Sites", "tags": "", "expected_text": ""}
        r = self.c.post(reverse("automation:template_apply", args=[t.pk]), data)
        u = UrlCheck.objects.get()
        self.assertRedirects(r, reverse("urlchecker:detail", args=[u.pk]), fetch_redirect_response=False)
        self.assertEqual((u.check_type, u.interval_seconds), ("api", 60))
        t.refresh_from_db()
        self.assertEqual(t.applied_count, 1)
        self.assertTrue(AuditEvent.objects.filter(action="apply", object_type="automation.template").exists())
        # applying again with the same name shows the model's uniqueness error instead of crashing
        r = self.c.post(reverse("automation:template_apply", args=[t.pk]), data)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(UrlCheck.objects.count(), 1)

    def test_apply_incident_and_viewer_denied(self):
        t = Template.objects.create(kind="incident", name="Overrun", fields={"title": "Overran", "priority": "P2"})
        self.login(self.viewer).post(reverse("automation:template_apply", args=[t.pk]), {"title": "x", "priority": "P2"})
        Ticket = apps.get_model("servicedesk", "Ticket")
        self.assertFalse(Ticket.objects.exists())
        r = self.login(self.operator).post(reverse("automation:template_apply", args=[t.pk]),
                                           {"title": "Overran", "priority": "P2", "site": "", "ci_name": "", "description": ""})
        ticket = Ticket.objects.get()
        self.assertRedirects(r, ticket.get_absolute_url(), fetch_redirect_response=False)

    def test_apply_requires_fields(self):
        t = Template.objects.create(kind="tcp_check", name="SSH", fields={"port": 22})
        r = self.login(self.operator).post(reverse("automation:template_apply", args=[t.pk]), {"port": "22", "site": "All Sites"})
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "This field is required")

    def test_delete_admin_only(self):
        t = Template.objects.create(kind="notification", name="N")
        self.login(self.operator).post(reverse("automation:template_delete", args=[t.pk]))
        self.assertTrue(Template.objects.exists())
        self.login(self.admin).post(reverse("automation:template_delete", args=[t.pk]))
        self.assertFalse(Template.objects.exists())


class SeedCommandTests(TestCase):
    def test_idempotent_and_rules_disabled(self):
        call_command("seed_automation", stdout=StringIO())
        call_command("seed_automation", stdout=StringIO())
        self.assertEqual(Runbook.objects.count(), 3)
        self.assertEqual(Template.objects.count(), 4)
        self.assertEqual(Rule.objects.count(), 3)
        self.assertFalse(Rule.objects.filter(enabled=True).exists())
        self.assertTrue(all(r.is_example for r in Runbook.objects.all()))
        self.assertTrue(all(r.name.startswith("Example") for r in Rule.objects.all()))
        self.assertEqual({t.kind for t in Template.objects.all()}, {"url_check", "tcp_check", "incident", "notification"})
        self.assertFalse(Execution.objects.exists())
        call_command("seed_automation", "--remove", stdout=StringIO())
        self.assertFalse(Runbook.objects.exists() or Rule.objects.exists() or Template.objects.exists())

    def test_example_last_reviewed_is_not_fabricated(self):
        call_command("seed_automation", stdout=StringIO())
        self.assertFalse(Runbook.objects.exclude(last_reviewed=None).exists())
        self.assertIsInstance(date.today(), date)
