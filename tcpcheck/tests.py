import csv
import io
import socket
import socketserver
import threading
from datetime import timedelta
from decimal import Decimal
from unittest import mock

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from core import jobs
from core.models import AuditEvent, Event, Membership, Site
from domainmonitor.models import Domain, DomainCheck
from urlchecker.models import UrlCheck, UrlResult

from . import probe, services, uptime
from .forms import TcpCheckForm
from .models import SlaTarget, Status, TcpCheck, TcpResult

LOCAL = override_settings(PROBE_ALLOWED_PRIVATE_CIDRS=["127.0.0.0/8"])


# ------------------------------------------------------------------ local TCP server
class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        if self.server.telnet:
            self.request.sendall(bytes([255, 253, 1, 255, 251, 3]))   # IAC DO ECHO, IAC WILL SGA
        if self.server.banner:
            self.request.sendall(self.server.banner)
        if self.server.hold:
            try:
                self.request.settimeout(self.server.hold)
                self.request.recv(64)
            except OSError:
                pass


class LocalServer:
    """A TCP server on 127.0.0.1 that optionally sends a banner first."""

    def __init__(self, banner=b"", telnet=False, hold=0.0):
        socketserver.ThreadingTCPServer.allow_reuse_address = True
        self.srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Handler)
        self.srv.daemon_threads = True
        self.srv.banner, self.srv.telnet, self.srv.hold = banner, telnet, hold
        self.port = self.srv.server_address[1]
        self.thread = threading.Thread(target=self.srv.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.srv.shutdown()
        self.srv.server_close()


def closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def make_check(**kw):
    defaults = {"name": "Probe", "host": "127.0.0.1", "port": 1, "site": "All Sites", "timeout_seconds": 2,
                "degraded_ms": 500}
    defaults.update(kw)
    return TcpCheck.objects.create(**defaults)


# ------------------------------------------------------------------ probe
@LOCAL
class ProbeTests(TestCase):
    def test_connect_ok(self):
        with LocalServer() as srv:
            r = probe.tcp_probe("127.0.0.1", srv.port, 2)
        self.assertTrue(r.ok)
        self.assertEqual(r.ip, "127.0.0.1")
        self.assertIsNotNone(r.response_ms)
        self.assertIsNone(r.banner_matched)

    def test_banner_matched(self):
        with LocalServer(banner=b"SSH-2.0-OpenSSH_9.6\r\n") as srv:
            r = probe.tcp_probe("127.0.0.1", srv.port, 2, expect_banner="SSH-")
        self.assertTrue(r.banner_matched)
        self.assertEqual(r.banner, "SSH-2.0-OpenSSH_9.6")

    def test_banner_mismatch(self):
        with LocalServer(banner=b"220 mail ESMTP\r\n") as srv:
            r = probe.tcp_probe("127.0.0.1", srv.port, 2, expect_banner="SSH-")
        self.assertTrue(r.ok)
        self.assertFalse(r.banner_matched)
        self.assertIn("220 mail", r.banner)

    def test_silent_server_times_out_reading_banner(self):
        with LocalServer(hold=3) as srv:
            r = probe.tcp_probe("127.0.0.1", srv.port, 1, expect_banner="SSH-")
        self.assertTrue(r.ok)
        self.assertFalse(r.banner_matched)
        self.assertEqual(r.banner, "")

    def test_telnet_negotiation_is_stripped(self):
        with LocalServer(banner=b"login: ", telnet=True) as srv:
            r = probe.tcp_probe("127.0.0.1", srv.port, 2, expect_banner="login:")
        self.assertTrue(r.banner_matched)
        self.assertEqual(r.banner, "login:")

    def test_parse_telnet_replies(self):
        text, replies = probe.parse_telnet(bytes([255, 253, 1, 65, 255, 255, 255, 251, 3, 66, 255, 250, 24, 1, 255, 240, 67]))
        self.assertEqual(text, b"A\xffBC")
        self.assertEqual(replies, bytes([255, 252, 1, 255, 254, 3]))

    def test_refused(self):
        r = probe.tcp_probe("127.0.0.1", closed_port(), 2)
        self.assertFalse(r.ok)
        self.assertIn("refused", r.error.lower())

    @override_settings(PROBE_ALLOWED_PRIVATE_CIDRS=[])
    def test_loopback_blocked_by_default(self):
        with LocalServer() as srv:
            r = probe.tcp_probe("127.0.0.1", srv.port, 2)
        self.assertFalse(r.ok)
        self.assertTrue(r.blocked)
        self.assertIn("probe policy", r.error)

    def test_metadata_address_always_blocked(self):
        r = probe.tcp_probe("169.254.169.254", 80, 1)
        self.assertTrue(r.blocked)

    def test_dns_failure(self):
        with mock.patch("probes.checks.resolve", side_effect=socket.gaierror(-2, "Name or service not known")):
            r = probe.tcp_probe("nope.invalid", 22, 1)
        self.assertFalse(r.ok)
        self.assertIn("DNS resolution failed", r.error)


# ------------------------------------------------------------------ services / jobs
@LOCAL
class ServiceTests(TestCase):
    def test_evaluate(self):
        c = TcpCheck(name="x", host="h", port=1, degraded_ms=100, expect_banner="")
        self.assertEqual(services.evaluate(c, probe.ProbeResult(ok=True, response_ms=20))[0], Status.ONLINE)
        self.assertEqual(services.evaluate(c, probe.ProbeResult(ok=True, response_ms=200))[0], Status.DEGRADED)
        self.assertEqual(services.evaluate(c, probe.ProbeResult(error="Connection refused"))[0], Status.DOWN)
        c.expect_banner = "SSH-"
        st, msg = services.evaluate(c, probe.ProbeResult(ok=True, response_ms=5, banner="220 hi", banner_matched=False))
        self.assertEqual(st, Status.DOWN)
        self.assertIn("SSH-", msg)

    def test_run_checks_stores_history_and_emits_on_change(self):
        with LocalServer(banner=b"SSH-2.0-x\r\n") as srv:
            c = make_check(port=srv.port, expect_banner="SSH-")
            self.assertEqual(services.run_checks([c]), [Status.ONLINE])
        c.refresh_from_db()
        self.assertEqual(c.last_status, Status.ONLINE)
        self.assertEqual(c.last_ip, "127.0.0.1")
        self.assertEqual(c.last_banner, "SSH-2.0-x")
        self.assertEqual(TcpResult.objects.filter(tcp_check=c).count(), 1)
        # unknown -> online is not news
        self.assertFalse(Event.objects.filter(fingerprint=f"tcp:{c.pk}").exists())

        c.port = closed_port()
        c.save()
        self.assertEqual(services.run_checks([c]), [Status.DOWN])
        ev = Event.objects.get(fingerprint=f"tcp:{c.pk}")
        self.assertEqual(ev.severity, "critical")
        self.assertEqual(ev.source, "tcpcheck")
        self.assertEqual(ev.data["previous"], "online")
        # same status again: no new event
        services.run_checks([c])
        self.assertEqual(Event.objects.filter(fingerprint=f"tcp:{c.pk}").count(), 1)
        self.assertEqual(TcpResult.objects.filter(tcp_check=c).count(), 3)

    def test_first_result_down_emits(self):
        c = make_check(port=closed_port())
        services.run_checks([c])
        self.assertEqual(Event.objects.get(fingerprint=f"tcp:{c.pk}").severity, "critical")

    def test_recovery_emits_ok(self):
        with LocalServer() as srv:
            c = make_check(port=srv.port, last_status=Status.DOWN)
            services.run_checks([c])
        self.assertEqual(Event.objects.get(fingerprint=f"tcp:{c.pk}").severity, "ok")

    def test_run_due_only_due_and_enabled(self):
        now = timezone.now()
        with LocalServer() as srv:
            due = make_check(name="due", port=srv.port)
            fresh = make_check(name="fresh", port=srv.port, last_checked_at=now - timedelta(seconds=10),
                               interval_seconds=60)
            off = make_check(name="off", port=srv.port, enabled=False)
            summary = services.run_due()
        self.assertIn("checked 1", summary)
        self.assertEqual(due.results.count(), 1)
        self.assertEqual(fresh.results.count(), 0)
        self.assertEqual(off.results.count(), 0)

    def test_run_due_never_raises(self):
        make_check()
        with mock.patch.object(services, "run_checks", side_effect=RuntimeError("boom")):
            self.assertEqual(services.run_due(), "error")

    def test_probe_crash_becomes_down(self):
        c = make_check()
        with mock.patch.object(services, "tcp_probe", side_effect=RuntimeError("bad")):
            self.assertEqual(services.run_checks([c]), [Status.DOWN])
        self.assertIn("Probe error", TcpResult.objects.get().message)

    @override_settings(PROBE_RETENTION_DAYS=30)
    def test_prune(self):
        c = make_check()
        now = timezone.now()
        TcpResult.objects.create(tcp_check=c, checked_at=now - timedelta(days=31), status="online")
        TcpResult.objects.create(tcp_check=c, checked_at=now - timedelta(days=2), status="online")
        self.assertIn("pruned 1", services.prune())
        self.assertEqual(TcpResult.objects.count(), 1)

    def test_jobs_registered(self):
        self.assertEqual(jobs.JOBS["tcpcheck.run_due"]["interval"], 15)
        self.assertIs(jobs.JOBS["tcpcheck.run_due"]["func"], services.run_due)
        self.assertIn("tcpcheck.prune", jobs.JOBS)


# ------------------------------------------------------------------ uptime
class UptimeTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_superuser("root", "r@example.com", "x")
        now = timezone.now()
        self.tcp = make_check(name="db", site="Mumbai", last_status="online")
        for i in range(10):   # 9 up, 1 down in the last 24h -> 90%
            TcpResult.objects.create(tcp_check=self.tcp, checked_at=now - timedelta(hours=i + 1),
                                     status="down" if i == 0 else "online")
        TcpResult.objects.create(tcp_check=self.tcp, checked_at=now - timedelta(days=20), status="online")
        self.url = UrlCheck.objects.create(name="web", url="https://example.com/", site="DR Site", last_status="degraded")
        for i in range(4):  # degraded counts as available -> 100%
            UrlResult.objects.create(url_check=self.url, checked_at=now - timedelta(hours=i + 1), status="degraded")
        self.dom = Domain.objects.create(tenant_key="default", site_key="Mumbai", hostname="example.com", status="up")
        DomainCheck.objects.create(domain=self.dom, checked_at=now - timedelta(days=3), up=True, dns_status="Resolved",
                                   ssl_status="Valid")
        DomainCheck.objects.create(domain=self.dom, checked_at=now - timedelta(days=3, hours=1), up=False,
                                   dns_status="Resolved", ssl_status="Valid")
        self.quiet = make_check(name="never checked", port=2)

    def test_collect_computes_windows(self):
        ts = {t.key: t for t in uptime.collect(self.admin)}
        tcp = ts[f"tcp:{self.tcp.pk}"]
        self.assertAlmostEqual(tcp.up24, 90.0)
        self.assertAlmostEqual(tcp.up30, 100.0 * 10 / 11)
        self.assertEqual(tcp.sla_state, "breached")
        url = ts[f"url:{self.url.pk}"]
        self.assertEqual(url.up24, 100.0)
        self.assertEqual(url.sla_state, "met")
        dom = ts[f"domain:{self.dom.pk}"]
        self.assertIsNone(dom.up24)
        self.assertEqual(dom.up7, 50.0)
        self.assertEqual(dom.status, "online")
        quiet = ts[f"tcp:{self.quiet.pk}"]
        self.assertIsNone(quiet.up30)
        self.assertEqual(quiet.sla_state, "nodata")

    def test_custom_sla_target(self):
        SlaTarget.objects.create(kind="tcp", object_id=self.tcp.pk, target=Decimal("90"))
        t = [t for t in uptime.collect(self.admin) if t.key == f"tcp:{self.tcp.pk}"][0]
        self.assertTrue(t.sla_custom)
        self.assertEqual(t.sla_state, "met")
        self.assertEqual(t.sla_display, "90")

    def test_filters(self):
        self.assertEqual({t.kind for t in uptime.collect(self.admin, kind="url")}, {"url"})
        self.assertEqual({t.name for t in uptime.collect(self.admin, site="Mumbai")}, {"db", "example.com"})
        self.assertEqual(sorted(t.name for t in uptime.collect(self.admin, q="exam")), ["example.com", "web"])
        self.assertEqual([t.name for t in uptime.collect(self.admin, kind="domain", q="exam")], ["example.com"])

    def test_daily_availability(self):
        data, has = uptime.daily_availability(uptime.sources(self.admin), days=30)
        self.assertTrue(has)
        self.assertEqual(len(data["labels"]), 30)
        names = [s["name"] for s in data["series"]]
        self.assertIn("Overall", names)
        self.assertEqual(data["yMax"], 100)

    def test_page_and_csv(self):
        c = Client()
        c.force_login(self.admin)
        r = c.get(reverse("tcpcheck:uptime"))
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Uptime Checks")
        self.assertContains(r, "Breached")
        r = c.get(reverse("tcpcheck:uptime") + "?type=tcp&sla=breached&days=7")
        self.assertContains(r, "db")
        self.assertNotContains(r, ">web<")
        r = c.get(reverse("tcpcheck:uptime_export") + "?type=tcp")
        rows = list(csv.reader(io.StringIO(r.content.decode())))
        self.assertEqual(rows[0][:3], ["type", "name", "target"])
        self.assertEqual({row[1] for row in rows[1:]}, {"db", "never checked"})

    def test_site_scoped_viewer_sees_only_their_targets(self):
        site = Site.objects.create(name="DR Site", code="dr")
        u = User.objects.create_user("drv")
        Membership.objects.create(user=u, site=site, role="viewer")
        names = {t.name for t in uptime.collect(u)}
        self.assertEqual(names, {"web", "never checked"})   # DR Site + "All Sites" records


# ------------------------------------------------------------------ views & permissions
@LOCAL
class ViewTests(TestCase):
    def setUp(self):
        self.viewer = User.objects.create_user("viewer", password="x")
        self.operator = User.objects.create_user("op", password="x", is_staff=True)
        self.admin = User.objects.create_superuser("root", "r@example.com", "x")
        self.check_obj = make_check(name="Core DB", port=closed_port(), site="Mumbai")
        TcpResult.objects.create(tcp_check=self.check_obj, checked_at=timezone.now(), status="down",
                                 message="Connection refused on port 1")

    def client_for(self, user):
        c = Client(enforce_csrf_checks=True)
        c.force_login(user)
        return c

    def token(self, c, url=None):
        c.get(url or reverse("tcpcheck:index"))
        return c.cookies["csrftoken"].value

    def test_pages_render_for_viewer(self):
        c = self.client_for(self.viewer)
        for url in (reverse("tcpcheck:index"), reverse("tcpcheck:detail", args=[self.check_obj.pk]),
                    reverse("tcpcheck:uptime"), reverse("tcpcheck:index") + "?events=all&status=down&q=core"):
            r = c.get(url)
            self.assertEqual(r.status_code, 200, url)
        r = c.get(reverse("tcpcheck:index"))
        self.assertContains(r, "Telnet Monitoring")
        self.assertContains(r, "Core DB")
        self.assertNotContains(r, 'action="/monitoring/telnet/new/"')
        self.assertNotContains(r, "Run Check Now")

    def test_empty_state(self):
        TcpCheck.objects.all().delete()
        r = self.client_for(self.viewer).get(reverse("tcpcheck:index"))
        self.assertContains(r, "No TCP checks yet")

    def test_export_csv(self):
        r = self.client_for(self.viewer).get(reverse("tcpcheck:export"))
        rows = list(csv.reader(io.StringIO(r.content.decode())))
        self.assertEqual(rows[0][0], "name")
        self.assertEqual(rows[1][:3], ["Core DB", "127.0.0.1", str(self.check_obj.port)])
        r = self.client_for(self.viewer).get(reverse("tcpcheck:history_export", args=[self.check_obj.pk]))
        self.assertIn("Connection refused", r.content.decode())

    def test_viewer_cannot_mutate(self):
        c = self.client_for(self.viewer)
        tok = self.token(c)
        r = c.post(reverse("tcpcheck:create"), {"csrfmiddlewaretoken": tok, "name": "x", "host": "127.0.0.1",
                                                 "port": 22, "interval_seconds": 60, "timeout_seconds": 5,
                                                 "degraded_ms": 500})
        self.assertEqual(r.status_code, 302)
        self.assertFalse(TcpCheck.objects.filter(name="x").exists())
        r = c.post(reverse("tcpcheck:run", args=[self.check_obj.pk]), {"csrfmiddlewaretoken": tok},
                   HTTP_ACCEPT="application/json", HTTP_X_CSRFTOKEN=tok)
        self.assertEqual(r.status_code, 403)
        self.assertEqual(c.get(reverse("tcpcheck:edit", args=[self.check_obj.pk])).status_code, 403)
        c.post(reverse("tcpcheck:delete", args=[self.check_obj.pk]), {"csrfmiddlewaretoken": tok})
        self.assertTrue(TcpCheck.objects.filter(pk=self.check_obj.pk).exists())

    def test_create_requires_csrf(self):
        c = self.client_for(self.operator)
        r = c.post(reverse("tcpcheck:create"), {"name": "x", "host": "127.0.0.1", "port": 22})
        self.assertEqual(r.status_code, 403)
        self.assertFalse(TcpCheck.objects.filter(name="x").exists())

    def test_operator_creates_runs_and_audits(self):
        c = self.client_for(self.operator)
        tok = self.token(c)
        with LocalServer(banner=b"SSH-2.0-test\r\n") as srv:
            r = c.post(reverse("tcpcheck:create"), {
                "csrfmiddlewaretoken": tok, "name": "Bastion", "host": "127.0.0.1", "port": srv.port,
                "interval_seconds": 60, "site": "", "tags": "ssh, ssh, prod", "expect_banner": "SSH-",
                "degraded_ms": 500, "timeout_seconds": 3, "enabled": "on"})
        self.assertRedirects(r, reverse("tcpcheck:index"), fetch_redirect_response=False)
        obj = TcpCheck.objects.get(name="Bastion")
        self.assertEqual(obj.site, "All Sites")
        self.assertEqual(obj.tags, "ssh, prod")
        self.assertEqual(obj.last_status, Status.ONLINE)
        self.assertTrue(AuditEvent.objects.filter(action="create", object_type="tcpcheck.tcpcheck",
                                                  object_id=str(obj.pk), actor=self.operator).exists())
        msgs = [str(m) for m in c.get(reverse("tcpcheck:index")).context["messages"]]
        self.assertTrue(any("Bastion" in m and "Online" in m for m in msgs))

    def test_invalid_form_rerenders(self):
        c = self.client_for(self.operator)
        tok = self.token(c)
        r = c.post(reverse("tcpcheck:create"), {"csrfmiddlewaretoken": tok, "name": "Core DB", "host": "http://x/",
                                                 "port": 70000, "interval_seconds": 60, "degraded_ms": 500,
                                                 "timeout_seconds": 5})
        self.assertEqual(r.status_code, 400)
        errors = r.context["form"].errors
        self.assertIn("name", errors)
        self.assertIn("host", errors)
        self.assertIn("port", errors)

    def test_operator_edit_audits_changes(self):
        c = self.client_for(self.operator)
        url = reverse("tcpcheck:edit", args=[self.check_obj.pk])
        tok = self.token(c, url)
        r = c.post(url, {"csrfmiddlewaretoken": tok, "name": "Core DB", "host": "127.0.0.1",
                         "port": self.check_obj.port, "interval_seconds": 300, "site": "Mumbai", "tags": "db",
                         "degraded_ms": 500, "timeout_seconds": 2})
        self.assertEqual(r.status_code, 302)
        self.check_obj.refresh_from_db()
        self.assertEqual(self.check_obj.interval_seconds, 300)
        self.assertFalse(self.check_obj.enabled)
        ev = AuditEvent.objects.get(action="update", object_id=str(self.check_obj.pk))
        self.assertEqual(ev.details["changed"]["interval_seconds"], ["60", "300"])

    def test_run_now_json_and_audit(self):
        c = self.client_for(self.operator)
        tok = self.token(c)
        r = c.post(reverse("tcpcheck:run", args=[self.check_obj.pk]), HTTP_X_CSRFTOKEN=tok,
                   HTTP_ACCEPT="application/json")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["status"], "down")
        self.assertTrue(AuditEvent.objects.filter(action="run", object_id=str(self.check_obj.pk)).exists())
        r = c.post(reverse("tcpcheck:run_all"), HTTP_X_CSRFTOKEN=tok, HTTP_ACCEPT="application/json")
        self.assertEqual(r.json()["checked"], 1)

    def test_run_now_rejects_get(self):
        r = self.client_for(self.operator).get(reverse("tcpcheck:run", args=[self.check_obj.pk]))
        self.assertEqual(r.status_code, 405)

    def test_delete_needs_admin(self):
        c = self.client_for(self.operator)
        tok = self.token(c)
        c.post(reverse("tcpcheck:delete", args=[self.check_obj.pk]), {"csrfmiddlewaretoken": tok})
        self.assertTrue(TcpCheck.objects.filter(pk=self.check_obj.pk).exists())
        c = self.client_for(self.admin)
        tok = self.token(c)
        r = c.post(reverse("tcpcheck:delete", args=[self.check_obj.pk]), {"csrfmiddlewaretoken": tok})
        self.assertRedirects(r, reverse("tcpcheck:index"), fetch_redirect_response=False)
        self.assertFalse(TcpCheck.objects.filter(pk=self.check_obj.pk).exists())
        self.assertFalse(TcpResult.objects.exists())
        self.assertTrue(AuditEvent.objects.filter(action="delete", object_id=str(self.check_obj.pk), actor=self.admin).exists())

    def test_site_scoped_operator(self):
        mum = Site.objects.create(name="Mumbai", code="mum")
        Site.objects.create(name="DR Site", code="dr")
        u = User.objects.create_user("mumop")
        Membership.objects.create(user=u, site=mum, role="operator")
        other = make_check(name="DR check", site="DR Site")
        c = self.client_for(u)
        self.assertEqual(c.get(reverse("tcpcheck:detail", args=[other.pk])).status_code, 404)
        tok = self.token(c)
        data = {"csrfmiddlewaretoken": tok, "name": "Mine", "host": "127.0.0.1", "port": 22, "interval_seconds": 60,
                "degraded_ms": 500, "timeout_seconds": 1}
        r = c.post(reverse("tcpcheck:create"), {**data, "site": "DR Site"})
        self.assertEqual(r.status_code, 400)
        self.assertFalse(TcpCheck.objects.filter(name="Mine").exists())
        r = c.post(reverse("tcpcheck:create"), {**data, "site": "Mumbai"})
        self.assertEqual(r.status_code, 302)
        self.assertTrue(TcpCheck.objects.filter(name="Mine", site="Mumbai").exists())

    def test_sla_update(self):
        url = reverse("tcpcheck:uptime")
        c = self.client_for(self.viewer)
        tok = self.token(c, url)
        c.post(reverse("tcpcheck:sla"), {"csrfmiddlewaretoken": tok, "kind": "tcp", "object_id": self.check_obj.pk,
                                         "target": "99.5"})
        self.assertFalse(SlaTarget.objects.exists())
        c = self.client_for(self.operator)
        tok = self.token(c, url)
        r = c.post(reverse("tcpcheck:sla"), {"csrfmiddlewaretoken": tok, "kind": "tcp", "object_id": self.check_obj.pk,
                                             "target": "99.5", "next": url + "?type=tcp"})
        self.assertRedirects(r, url + "?type=tcp", fetch_redirect_response=False)
        self.assertEqual(SlaTarget.objects.get().target, Decimal("99.5"))
        self.assertTrue(AuditEvent.objects.filter(action="update", object_type="tcpcheck.slatarget").exists())
        # out of range and unknown targets are refused
        c.post(reverse("tcpcheck:sla"), {"csrfmiddlewaretoken": tok, "kind": "tcp", "object_id": self.check_obj.pk,
                                         "target": "120"})
        c.post(reverse("tcpcheck:sla"), {"csrfmiddlewaretoken": tok, "kind": "url", "object_id": 99999, "target": "99"})
        self.assertEqual(SlaTarget.objects.count(), 1)
        self.assertEqual(SlaTarget.objects.get().target, Decimal("99.5"))

    def test_open_redirect_ignored(self):
        c = self.client_for(self.operator)
        tok = self.token(c)
        r = c.post(reverse("tcpcheck:run", args=[self.check_obj.pk]), {"csrfmiddlewaretoken": tok,
                                                                       "next": "https://evil.example/"})
        self.assertEqual(r["Location"], self.check_obj.get_absolute_url())


# ------------------------------------------------------------------ forms & seed
class FormTests(TestCase):
    def form(self, **kw):
        data = {"name": "n", "host": "db.example.com", "port": 22, "interval_seconds": 60, "degraded_ms": 500,
                "timeout_seconds": 5}
        data.update(kw)
        return TcpCheckForm(data)

    def test_valid_hostname_normalised(self):
        f = self.form(host="DB.Example.COM.")
        self.assertTrue(f.is_valid(), f.errors)
        self.assertEqual(f.cleaned_data["host"], "db.example.com")

    def test_rejects_url_and_port_in_host(self):
        self.assertIn("host", self.form(host="https://db.example.com").errors)
        self.assertIn("host", self.form(host="db.example.com:22").errors)

    def test_rejects_blocked_ip_literal(self):
        self.assertIn("host", self.form(host="169.254.169.254").errors)
        self.assertIn("host", self.form(host="10.0.0.5").errors)

    @override_settings(PROBE_ALLOWED_PRIVATE_CIDRS=["10.0.0.0/8"])
    def test_allows_allowlisted_private_ip_and_ipv6(self):
        self.assertTrue(self.form(host="10.0.0.5").is_valid())
        f = self.form(host="[2606:4700:4700::1111]")
        self.assertTrue(f.is_valid(), f.errors)
        self.assertEqual(f.cleaned_data["host"], "2606:4700:4700::1111")

    def test_degraded_must_be_below_timeout(self):
        self.assertIn("degraded_ms", self.form(degraded_ms=5000, timeout_seconds=5).errors)

    def test_target_property(self):
        self.assertEqual(TcpCheck(host="::1", port=22).target, "[::1]:22")
        self.assertEqual(TcpCheck(host="h", port=22).target, "h:22")


class SeedTests(TestCase):
    def test_seed_is_idempotent_and_marked(self):
        out = io.StringIO()
        call_command("seed_tcpcheck", stdout=out)
        n = TcpCheck.objects.count()
        call_command("seed_tcpcheck", stdout=out)
        self.assertEqual(TcpCheck.objects.count(), n)
        self.assertTrue(all("example" in c.tags and c.name.startswith("Example") for c in TcpCheck.objects.all()))
        self.assertFalse(TcpResult.objects.exists())   # no fabricated history
        call_command("seed_tcpcheck", "--remove", stdout=out)
        self.assertFalse(TcpCheck.objects.exists())


class FilterTests(TestCase):
    def test_connect_ms(self):
        from .templatetags.tcpcheck_tags import connect_ms
        self.assertEqual(connect_ms(0.2), "<1 ms")
        self.assertEqual(connect_ms(12.4), "12 ms")
        self.assertEqual(connect_ms(None), "–")
