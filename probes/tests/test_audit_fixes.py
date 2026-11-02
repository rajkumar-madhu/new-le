"""Regression tests for the probes audit findings (SSRF range, overall deadline,
tenant scoping, deleted-check race, HEAD + expected text)."""
import http.server
import socket
import threading
import time
from io import StringIO
from unittest import mock

from django.core.management import call_command
from django.test import SimpleTestCase, TestCase, TransactionTestCase, override_settings

from domainmonitor.models import Domain, DomainCheck
from probes import checks, runner
from urlchecker.models import UrlCheck, UrlResult


def fake_http(status=200, ms=120.0):
    return checks.HttpResult(ok=True, status=status, response_ms=ms, ip="93.184.216.34")


# ------------------------------------------------------------ 1. CGNAT / non-global ranges
class NonGlobalRangeTests(SimpleTestCase):
    @override_settings(PROBE_ALLOWED_PRIVATE_CIDRS=[])
    def test_shared_address_space_is_refused_by_default(self):
        # 100.64.0.0/10 is neither private nor reserved for Python, but it is not global either.
        for ip in ("100.100.100.200", "100.64.0.1", "100.127.255.254", "192.0.0.8", "::ffff:100.100.100.200"):
            with self.assertRaises(checks.ProbeBlocked, msg=ip):
                checks.check_address(ip)

    @override_settings(PROBE_ALLOWED_PRIVATE_CIDRS=["100.64.0.0/10"])
    def test_shared_address_space_can_be_opted_in(self):
        checks.check_address("100.100.100.200")

    @override_settings(PROBE_ALLOWED_PRIVATE_CIDRS=[])
    def test_public_addresses_still_allowed(self):
        for ip in ("93.184.216.34", "8.8.8.8", "2606:4700:4700::1111"):
            checks.check_address(ip)

    @override_settings(PROBE_ALLOWED_PRIVATE_CIDRS=[])
    def test_http_check_does_not_connect_to_shared_space(self):
        info = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("100.100.100.200", 80))]
        with mock.patch.object(checks.socket, "getaddrinfo", return_value=info), \
             mock.patch.object(checks.socket, "create_connection", side_effect=AssertionError("connected")) as conn:
            r = checks.http_check("http://metadata.internal/latest/meta-data/", expected_text="x")
        conn.assert_not_called()
        self.assertFalse(r.ok)
        self.assertIn("Blocked by probe policy", r.error)


# ------------------------------------------------------------ 2. overall deadline
class _TrickleServer:
    """Accepts one connection at a time, sends `prefix`, then one byte every `gap`
    seconds until `limit` seconds have passed or the client goes away."""

    def __init__(self, prefix, gap=0.25, limit=5.0):
        self.prefix, self.gap, self.limit = prefix, gap, limit
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.stopped = False
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while not self.stopped:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(c,), daemon=True).start()

    def _handle(self, c):
        end = time.monotonic() + self.limit
        try:
            c.settimeout(0.5)
            try:
                c.recv(65536)
            except socket.timeout:
                pass
            c.sendall(self.prefix)
            while time.monotonic() < end and not self.stopped:
                c.sendall(b"a")
                time.sleep(self.gap)
        except OSError:
            pass
        finally:
            c.close()

    def close(self):
        self.stopped = True
        self.sock.close()


@override_settings(PROBE_ALLOWED_PRIVATE_CIDRS=["127.0.0.0/8"])
class DeadlineTests(SimpleTestCase):
    def run_against(self, prefix, fn):
        srv = _TrickleServer(prefix)
        try:
            started = time.monotonic()
            r = fn(srv.port)
            return r, time.monotonic() - started
        finally:
            srv.close()

    def test_trickled_body_hits_overall_deadline(self):
        prefix = b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n"
        r, elapsed = self.run_against(prefix, lambda p: checks.http_check(f"http://127.0.0.1:{p}/", timeout=1))
        self.assertLess(elapsed, 3.0)
        self.assertFalse(r.ok)
        self.assertIn("Timed out", r.error)

    def test_trickled_headers_hit_overall_deadline(self):
        prefix = b"HTTP/1.1 200 OK\r\nX-Slow: "
        r, elapsed = self.run_against(prefix, lambda p: checks.http_check(f"http://127.0.0.1:{p}/", timeout=1))
        self.assertLess(elapsed, 3.0)
        self.assertFalse(r.ok)
        self.assertIn("Timed out", r.error)

    def test_trickled_tls_handshake_hits_deadline(self):
        # A TLS record header announcing a 16 KiB handshake record, then the record trickles in.
        prefix = b"\x16\x03\x03\x40\x00"
        r, elapsed = self.run_against(prefix, lambda p: checks.tls_check("localhost", port=p, timeout=1))
        self.assertLess(elapsed, 3.0)
        self.assertEqual(r.status, "Unreachable")

    def test_fast_response_unaffected(self):
        prefix = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
        srv = _TrickleServer(prefix, limit=0)
        try:
            r = checks.http_check(f"http://127.0.0.1:{srv.port}/", timeout=2, expected_text="ok")
        finally:
            srv.close()
        self.assertTrue(r.ok, r.error)
        self.assertEqual(r.status, 200)
        self.assertTrue(r.body_matched)


# ------------------------------------------------------------ 3. tenant scoping of the scheduler
@override_settings(LINKEDEYE_TENANT="default")
class RunDueTenantTests(TestCase):
    def test_run_due_only_probes_this_tenant(self):
        mine_url = UrlCheck.objects.create(tenant_key="default", name="Mine", url="https://mine.example/")
        UrlCheck.objects.create(tenant_key="other", name="Theirs", url="https://theirs.example/")
        mine_dom = Domain.objects.create(tenant_key="default", site_key="s", hostname="mine.example")
        Domain.objects.create(tenant_key="other", site_key="s", hostname="other.example", status="up")
        seen_urls, seen_domains = [], []
        with mock.patch.object(runner, "run_url_checks", side_effect=lambda items: seen_urls.extend(items)), \
             mock.patch.object(runner, "run_domain_checks", side_effect=lambda items: seen_domains.extend(items)):
            self.assertEqual(runner.run_due(), (1, 1))
        self.assertEqual(seen_urls, [mine_url])
        self.assertEqual(seen_domains, [mine_dom])

    @override_settings(INCIDENT_AUTO_CREATE=True)
    def test_other_tenant_outage_creates_no_event(self):
        from core.models import Event
        Domain.objects.create(tenant_key="other", site_key="s", hostname="other.example", status="up")
        down = (checks.DnsResult(False, [], "DNS resolution failed"), None, None)
        with mock.patch.object(runner, "_probe_domain", return_value=down):
            runner.run_due()
        self.assertFalse(Event.objects.filter(title__contains="other.example").exists())
        self.assertEqual(Domain.objects.get(hostname="other.example").status, "up")


# ------------------------------------------------------------ 4. check deleted while its probe is in flight
class DeletedDuringProbeTests(TransactionTestCase):
    def test_deleted_url_check_does_not_abort_the_batch(self):
        a = UrlCheck.objects.create(name="a", url="https://a.example/")
        b = UrlCheck.objects.create(name="b", url="https://b.example/")

        def probe(check):
            if check.name == "b":
                UrlCheck.objects.filter(pk=a.pk).delete()
            return fake_http()

        with mock.patch.object(runner, "_probe_url", side_effect=probe), \
             mock.patch.object(runner.settings, "PROBE_WORKERS", 1):
            statuses = runner.run_url_checks([a, b])
        self.assertEqual(statuses, [None, "online"])
        b.refresh_from_db()
        self.assertIsNotNone(b.last_checked_at)
        self.assertEqual(UrlResult.objects.filter(url_check=b).count(), 1)
        self.assertEqual(UrlResult.objects.count(), 1)

    def test_deleted_domain_does_not_abort_the_batch(self):
        a = Domain.objects.create(tenant_key="default", site_key="s", hostname="a.example")
        b = Domain.objects.create(tenant_key="default", site_key="s", hostname="b.example")
        ok = (checks.DnsResult(True, ["93.184.216.34"]), fake_http(), None)

        def probe(domain):
            if domain.hostname == "b.example":
                Domain.objects.filter(pk=a.pk).delete()
            return ok

        with mock.patch.object(runner, "_probe_domain", side_effect=probe), \
             mock.patch.object(runner.settings, "PROBE_WORKERS", 1):
            statuses = runner.run_domain_checks([a, b])
        self.assertEqual(statuses, [None, "up"])
        self.assertEqual(DomainCheck.objects.filter(domain=b).count(), 1)
        self.assertEqual(DomainCheck.objects.count(), 1)

    def test_run_due_still_reaches_domain_checks(self):
        a = UrlCheck.objects.create(name="a", url="https://a.example/")
        with mock.patch.object(runner, "_probe_url", side_effect=lambda c: (UrlCheck.objects.filter(pk=a.pk).delete(), fake_http())[1]), \
             mock.patch.object(runner, "run_domain_checks") as doms:
            runner.run_due()
        doms.assert_called_once()


class RunProbesCommandTests(TestCase):
    def test_jobs_run_even_if_probe_pass_fails(self):
        with mock.patch.object(runner, "run_due", side_effect=RuntimeError("boom")), \
             mock.patch("core.jobs.run_due", return_value={}) as jobs_due, \
             mock.patch.object(runner, "prune", return_value=0):
            call_command("run_probes", "--once", stdout=StringIO())
        jobs_due.assert_called_once()


# ------------------------------------------------------------ 5. HEAD + expected text
class _HeadHandler(http.server.BaseHTTPRequestHandler):
    def _respond(self, with_body):
        if self.path == "/see-other":
            self.send_response(303)
            self.send_header("Location", "/ok")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        body = b"status: OK"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if with_body:
            self.wfile.write(body)

    def do_GET(self):
        self._respond(True)

    def do_HEAD(self):
        self._respond(False)

    def log_message(self, *a):
        pass


@override_settings(PROBE_ALLOWED_PRIVATE_CIDRS=["127.0.0.0/8"], PROBE_TIMEOUT=5)
class HeadExpectedTextTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.httpd = http.server.HTTPServer(("127.0.0.1", 0), _HeadHandler)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        super().tearDownClass()

    def url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def test_head_with_expected_text_is_not_a_body_mismatch(self):
        r = checks.http_check(self.url("/ok"), method="HEAD", expected_text="OK")
        self.assertTrue(r.ok, r.error)
        self.assertIsNone(r.body_matched)

    def test_head_303_to_get_still_matches_body(self):
        r = checks.http_check(self.url("/see-other"), method="HEAD", expected_text="OK")
        self.assertEqual(r.status, 200)
        self.assertTrue(r.body_matched)

    def test_head_check_with_expected_text_is_online(self):
        check = UrlCheck.objects.create(name="h", url=self.url("/ok"), method="HEAD", expected_text="OK",
                                        degraded_ms=5000)
        self.assertEqual(runner.run_url_checks([check]), ["online"])


# ------------------------------------------------------------ review follow-ups
class EmbeddedIPv4Tests(SimpleTestCase):
    @override_settings(PROBE_ALLOWED_PRIVATE_CIDRS=[])
    def test_nat64_and_site_local_forms_of_internal_addresses_are_refused(self):
        # A NAT64 gateway turns 64:ff9b::a.b.c.d into a.b.c.d; Python calls these addresses global.
        for ip in ("64:ff9b::a00:5", "64:ff9b::a64:64c8", "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe",
                   "::ffff:0:a00:5", "fec0::1"):
            with self.assertRaises(checks.ProbeBlocked, msg=ip):
                checks.check_address(ip)

    @override_settings(PROBE_ALLOWED_PRIVATE_CIDRS=[])
    def test_nat64_form_of_public_address_is_allowed(self):
        checks.check_address("64:ff9b::808:808")

    @override_settings(PROBE_ALLOWED_PRIVATE_CIDRS=["10.0.0.0/8"])
    def test_nat64_form_follows_the_ipv4_opt_in(self):
        checks.check_address("64:ff9b::a00:5")


class SaveErrorTests(TestCase):
    def test_database_error_for_an_existing_check_is_not_swallowed(self):
        from django.db import OperationalError
        c = UrlCheck.objects.create(name="c", url="https://c.example/")
        with mock.patch.object(runner.UrlResult.objects, "create", side_effect=OperationalError("disk I/O error")):
            with self.assertRaises(OperationalError):
                runner.save_url_result(c, fake_http(), runner.timezone.now())

    def test_database_error_for_an_existing_domain_is_not_swallowed(self):
        from django.db import OperationalError
        d = Domain.objects.create(tenant_key="default", site_key="s", hostname="d.example")
        probe = (checks.DnsResult(True, ["93.184.216.34"]), fake_http(), None)
        with mock.patch.object(runner.DomainCheck.objects, "create", side_effect=OperationalError("disk I/O error")):
            with self.assertRaises(OperationalError):
                runner.save_domain_result(d, probe, runner.timezone.now())


@override_settings(LINKEDEYE_TENANT="default", PROBE_RETENTION_DAYS=30)
class PruneTenantTests(TestCase):
    def test_prune_leaves_other_tenants_history_alone(self):
        from datetime import timedelta
        old = runner.timezone.now() - timedelta(days=40)
        mine = UrlCheck.objects.create(tenant_key="default", name="m", url="https://m.example/")
        theirs = UrlCheck.objects.create(tenant_key="other", name="t", url="https://t.example/")
        md = Domain.objects.create(tenant_key="default", site_key="s", hostname="m.example")
        td = Domain.objects.create(tenant_key="other", site_key="s", hostname="t.example")
        for c in (mine, theirs):
            UrlResult.objects.create(url_check=c, checked_at=old, status="online")
        for d in (md, td):
            DomainCheck.objects.create(domain=d, checked_at=old, up=True)
        self.assertEqual(runner.prune(), 2)
        self.assertEqual(list(UrlResult.objects.values_list("url_check__tenant_key", flat=True)), ["other"])
        self.assertEqual(list(DomainCheck.objects.values_list("domain__tenant_key", flat=True)), ["other"])
