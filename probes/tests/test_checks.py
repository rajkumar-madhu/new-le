import http.server
import socket
import threading
from datetime import datetime, timedelta, timezone

from django.test import SimpleTestCase, override_settings

from probes import checks


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redirect-to-metadata":
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.end_headers()
            return
        if self.path == "/redirect":
            self.send_response(301)
            self.send_header("Location", "/ok")
            self.end_headers()
            return
        body = b"hello linkedeye" if self.path == "/ok" else b"nope"
        self.send_response(200 if self.path == "/ok" else 503)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class ServerMixin:
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.httpd.server_address[1]
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        super().tearDownClass()


class PolicyTests(SimpleTestCase):
    @override_settings(PROBE_ALLOWED_PRIVATE_CIDRS=[])
    def test_blocks_private_loopback_and_metadata(self):
        for ip in ("10.10.1.21", "127.0.0.1", "192.168.1.1", "169.254.169.254", "::1", "0.0.0.0"):
            with self.assertRaises(checks.ProbeBlocked, msg=ip):
                checks.check_address(ip)

    @override_settings(PROBE_ALLOWED_PRIVATE_CIDRS=["10.10.0.0/16"])
    def test_allowlisted_private_range(self):
        checks.check_address("10.10.1.21")
        with self.assertRaises(checks.ProbeBlocked):
            checks.check_address("10.20.1.1")

    @override_settings(PROBE_ALLOWED_PRIVATE_CIDRS=["0.0.0.0/0"])
    def test_link_local_always_blocked(self):
        with self.assertRaises(checks.ProbeBlocked):
            checks.check_address("169.254.169.254")

    def test_public_allowed(self):
        checks.check_address("93.184.216.34")

    def test_tls_status_thresholds(self):
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.assertEqual(checks.tls_status(now + timedelta(days=90), now)[0], "Valid")
        self.assertEqual(checks.tls_status(now + timedelta(days=10), now)[0], "Expiring")
        self.assertEqual(checks.tls_status(now - timedelta(days=1), now)[0], "Expired")


@override_settings(PROBE_ALLOWED_PRIVATE_CIDRS=["127.0.0.0/8"], PROBE_TIMEOUT=5)
class HttpCheckTests(ServerMixin, SimpleTestCase):
    def url(self, path):
        return f"http://127.0.0.1:{self.port}{path}"

    def test_ok_with_text(self):
        r = checks.http_check(self.url("/ok"), expected_text="linkedeye")
        self.assertTrue(r.ok)
        self.assertEqual(r.status, 200)
        self.assertTrue(r.body_matched)
        self.assertIsNotNone(r.response_ms)

    def test_follows_redirect(self):
        r = checks.http_check(self.url("/redirect"))
        self.assertEqual((r.status, r.final_url), (200, self.url("/ok")))

    def test_redirect_into_blocked_range_is_refused(self):
        r = checks.http_check(self.url("/redirect-to-metadata"))
        self.assertFalse(r.ok)
        self.assertIn("Blocked by probe policy", r.error)

    def test_http_error_status_is_reported(self):
        r = checks.http_check(self.url("/broken"))
        self.assertTrue(r.ok)
        self.assertEqual(r.status, 503)

    def test_connection_refused(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        r = checks.http_check(f"http://127.0.0.1:{port}/")
        self.assertFalse(r.ok)
        self.assertIn("refused", r.error.lower())

    @override_settings(PROBE_ALLOWED_PRIVATE_CIDRS=[])
    def test_loopback_blocked_by_default(self):
        r = checks.http_check(self.url("/ok"))
        self.assertFalse(r.ok)
        self.assertIn("Blocked", r.error)
