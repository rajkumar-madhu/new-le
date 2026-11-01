"""Security scanner, grading, job and analytics helpers (network calls are mocked)."""
import ssl
from datetime import datetime, timedelta, timezone as dt_timezone
from unittest import mock

from django.test import TestCase
from django.utils import timezone

from core.jobs import JOBS
from core.models import Event
from probes import checks

from . import analytics, security
from .models import Domain, DomainCheck, DomainSecurityScan

GOOD_HEADERS = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=()",
    "server": "nginx",
}


def facts(**kw):
    base = dict(hostname="example.com", ip="93.184.216.34", final_url="https://example.com/", http_status=200,
                tls_version="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384", cert_issuer="Let's Encrypt",
                cert_subject="example.com", cert_expires_at=datetime.now(dt_timezone.utc) + timedelta(days=80),
                cert_valid=True, https_redirect=True, http_note="HTTP 301 → https://example.com/",
                headers=dict(GOOD_HEADERS))
    base.update(kw)
    return security.ScanData(**base)


class GradingTests(TestCase):
    def keys_failed(self, findings):
        return {f["key"] for f in findings if not f["passed"]}

    def test_hardened_site_gets_a(self):
        grade, score, findings = security.evaluate(facts())
        self.assertEqual((grade, score), ("A", 100))
        self.assertEqual(len(findings), len(security.CHECKS))
        self.assertTrue(all(f["recommendation"] == "" for f in findings))

    def test_missing_headers_lower_the_grade(self):
        grade, score, findings = security.evaluate(facts(headers={"server": "nginx"}))
        self.assertEqual(self.keys_failed(findings), {"hsts", "csp", "x_frame_options", "x_content_type_options",
                                                       "referrer_policy", "permissions_policy"})
        self.assertEqual(score, 100 - 20 - 15 - 10 - 10 - 5 - 5)
        self.assertEqual(grade, "F")
        hsts = next(f for f in findings if f["key"] == "hsts")
        self.assertIn("Strict-Transport-Security", hsts["recommendation"])

    def test_grade_bands(self):
        h = dict(GOOD_HEADERS)
        del h["content-security-policy"]            # -15 (frame protection still via X-Frame-Options)
        self.assertEqual(security.evaluate(facts(headers=h))[:2], ("B", 85))
        h.pop("permissions-policy")
        h.pop("referrer-policy")                     # -5 -5
        self.assertEqual(security.evaluate(facts(headers=h))[:2], ("C", 75))

    def test_untrusted_certificate_is_f(self):
        grade, score, findings = security.evaluate(facts(cert_valid=False, cert_error="self-signed certificate",
                                                         cert_expires_at=None, cert_issuer=""))
        self.assertEqual(grade, "F")
        self.assertLessEqual(score, 49)
        self.assertIn("cert_valid", self.keys_failed(findings))

    def test_old_tls_is_f_and_weak_cipher_flagged(self):
        grade, _score, findings = security.evaluate(facts(tls_version="TLSv1.1", cipher="AES128-SHA"))
        self.assertEqual(grade, "F")
        self.assertTrue({"tls_version", "tls13", "cipher"} <= self.keys_failed(findings))
        _g, _s, findings = security.evaluate(facts(tls_version="TLSv1.2", cipher="ECDHE-RSA-AES128-GCM-SHA256"))
        self.assertEqual(self.keys_failed(findings), {"tls13"})

    def test_header_details(self):
        h = dict(GOOD_HEADERS, **{"strict-transport-security": "max-age=300", "server": "Apache/2.4.41 (Ubuntu)",
                                  "x-powered-by": "PHP/8.1", "referrer-policy": "unsafe-url"})
        h.pop("x-frame-options")   # CSP frame-ancestors still protects against framing
        _g, _s, findings = security.evaluate(facts(headers=h, https_redirect=False, http_note="HTTP 200 served over plain HTTP"))
        self.assertEqual(self.keys_failed(findings), {"hsts", "server_disclosure", "referrer_policy", "https_redirect"})
        server = next(f for f in findings if f["key"] == "server_disclosure")
        self.assertIn("Apache/2.4.41", server["detail"])
        self.assertIn("PHP/8.1", server["detail"])

    def test_csp_unsafe_inline_is_noted(self):
        h = dict(GOOD_HEADERS, **{"content-security-policy": "script-src 'self' 'unsafe-inline'"})
        csp = next(f for f in security.evaluate(facts(headers=h))[2] if f["key"] == "csp")
        self.assertTrue(csp["passed"])
        self.assertIn("unsafe-inline", csp["detail"])

    def test_expiring_certificate(self):
        soon = datetime.now(dt_timezone.utc) + timedelta(days=10)
        _g, score, findings = security.evaluate(facts(cert_expires_at=soon))
        self.assertEqual(self.keys_failed(findings), {"cert_expiry"})
        self.assertEqual(score, 80)

    def test_port_80_closed_passes_redirect_check(self):
        _g, score, _f = security.evaluate(facts(https_redirect=None, http_note="Port 80 not reachable"))
        self.assertEqual(score, 100)

    def test_failed_scan_is_not_graded(self):
        self.assertEqual(security.evaluate(security.ScanData(hostname="x.test", error="DNS resolution failed")), ("", None, []))


def tls_info(version="TLSv1.3", cert=True):
    c = {"issuer": ((("organizationName", "Let's Encrypt"),), (("commonName", "R11"),)),
         "subject": ((("commonName", "example.com"),),), "notAfter": "Jan  1 00:00:00 2099 GMT"} if cert else {}
    return {"version": version, "cipher": "TLS_AES_256_GCM_SHA384", "cert": c}


@mock.patch.object(security, "_http_redirects", return_value=(True, "HTTP 301 → https://example.com/"))
class ScanHostTests(TestCase):
    """scan_host must go through the SSRF policy and only ever read response headers."""

    @mock.patch.object(checks, "resolve_allowed", return_value="93.184.216.34")
    @mock.patch.object(security, "_https_headers")
    def test_collects_tls_and_headers(self, https, resolve, _redir):
        https.return_value = (200, dict(GOOD_HEADERS), None, tls_info())
        data = security.scan_host("example.com", timeout=3)
        resolve.assert_called_once_with("example.com", 443)
        https.assert_called_once_with("example.com", "93.184.216.34", 443, "/", 3, True)
        self.assertEqual((data.error, data.tls_version, data.cert_issuer, data.cert_subject), ("", "TLSv1.3", "Let's Encrypt", "example.com"))
        self.assertTrue(data.cert_valid)
        self.assertEqual(data.cert_expires_at.year, 2099)
        self.assertTrue(data.https_redirect)
        self.assertEqual(security.evaluate(data)[0], "A")

    @mock.patch.object(checks, "resolve_allowed", side_effect=checks.ProbeBlocked("169.254.169.254 is in a blocked range"))
    @mock.patch.object(security, "_https_headers")
    def test_blocked_address_never_connects(self, https, _resolve, redir):
        data = security.scan_host("metadata.test")
        self.assertIn("Blocked by probe policy", data.error)
        https.assert_not_called()
        redir.assert_not_called()

    @mock.patch.object(checks, "resolve_allowed", return_value="203.0.113.5")
    @mock.patch.object(security, "_https_headers")
    def test_follows_https_redirect_with_a_new_policy_check(self, https, resolve, _redir):
        https.side_effect = [(301, {}, "https://www.example.com/home", tls_info()),
                             (200, dict(GOOD_HEADERS), None, tls_info("TLSv1.2"))]
        data = security.scan_host("example.com")
        self.assertEqual([c.args for c in resolve.call_args_list], [("example.com", 443), ("www.example.com", 443)])
        self.assertEqual(data.final_url, "https://www.example.com/home")
        self.assertEqual(data.tls_version, "TLSv1.3")   # TLS facts describe the domain itself (first hop)
        self.assertEqual(data.headers["x-frame-options"], "DENY")

    @mock.patch.object(checks, "resolve_allowed", return_value="203.0.113.5")
    @mock.patch.object(security, "_https_headers")
    def test_untrusted_certificate_still_reads_headers(self, https, _resolve, _redir):
        err = ssl.SSLCertVerificationError("certificate verify failed")
        err.verify_message = "self-signed certificate"
        https.side_effect = [err, (200, {"server": "nginx"}, None, tls_info(cert=False))]
        data = security.scan_host("self-signed.example")
        self.assertEqual(https.call_args_list[1].args[-1], False)   # second attempt without verification
        self.assertFalse(data.cert_valid)
        self.assertEqual(data.cert_error, "self-signed certificate")
        self.assertEqual(security.evaluate(data)[0], "F")

    @mock.patch.object(checks, "resolve_allowed", return_value="203.0.113.5")
    @mock.patch.object(security, "_https_headers", side_effect=ConnectionRefusedError())
    def test_connection_refused(self, _https, _resolve, redir):
        data = security.scan_host("closed.example")
        self.assertEqual(data.error, "Connection refused on port 443")
        redir.assert_not_called()


class FakeConn:
    """Stands in for the pinned HTTPS connection: records what was requested, serves headers only."""
    instances = []

    def __init__(self, host, ip, port, timeout, context):
        self.host, self.ip, self.port, self.context = host, ip, port, context
        self.sock = mock.Mock(**{"version.return_value": "TLSv1.3", "cipher.return_value": ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128),
                                 "getpeercert.return_value": tls_info()["cert"]})
        self.resp = mock.Mock(status=200, **{"getheaders.return_value": [("Server", "nginx"), ("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")],
                                             "getheader.return_value": None})
        FakeConn.instances.append(self)

    def request(self, method, path, headers):
        self.method, self.path = method, path

    def getresponse(self):
        return self.resp

    def close(self):
        self.closed = True


class PinnedRequestTests(TestCase):
    def test_uses_pinned_connection_and_never_reads_the_body(self):
        FakeConn.instances = []
        with mock.patch.object(checks, "_PinnedHTTPSConnection", FakeConn):
            status, headers, location, tls = security._https_headers("example.com", "203.0.113.5", 443, "/", 5, True)
        conn = FakeConn.instances[0]
        self.assertEqual((conn.host, conn.ip, conn.port, conn.method), ("example.com", "203.0.113.5", 443, "GET"))
        self.assertTrue(conn.context.check_hostname)
        conn.resp.read.assert_not_called()
        self.assertTrue(conn.closed)
        self.assertEqual(headers, {"server": "nginx", "set-cookie": "a=1, b=2"})
        self.assertEqual((status, tls["version"]), (200, "TLSv1.3"))


class ScanStorageAndJobTests(TestCase):
    def setUp(self):
        self.a = Domain.objects.create(tenant_key="default", hostname="a.example.com", site_key="Mumbai")
        self.b = Domain.objects.create(tenant_key="default", hostname="b.example.com")
        self.off = Domain.objects.create(tenant_key="default", hostname="off.example.com", is_active=False)

    def test_job_is_registered(self):
        self.assertIn("domainmonitor.security_scan", JOBS)
        self.assertIs(JOBS["domainmonitor.security_scan"]["func"], security.scheduled_scan)

    def test_save_scan_stores_fields_and_emits_on_grade_change(self):
        s1 = security.save_scan(self.a, facts(hostname=self.a.hostname))
        self.assertEqual((s1.grade, s1.score, s1.tls_version, s1.x_frame_options), ("A", 100, "TLSv1.3", "DENY"))
        self.assertEqual(s1.cert_days_left, 79)
        self.assertFalse(Event.objects.filter(fingerprint=f"domainsec:{self.a.pk}").exists())   # first scan: no event
        s2 = security.save_scan(self.a, facts(hostname=self.a.hostname, headers={}))
        self.assertEqual(s2.grade, "F")
        ev = Event.objects.get(fingerprint=f"domainsec:{self.a.pk}")
        self.assertEqual((ev.severity, ev.data["previous"], ev.data["grade"]), ("warning", "A", "F"))
        security.save_scan(self.a, facts(hostname=self.a.hostname))
        self.assertEqual(Event.objects.filter(fingerprint=f"domainsec:{self.a.pk}", severity="ok").count(), 1)
        self.assertEqual(security.latest_scans([self.a.pk, self.b.pk])[self.a.pk].grade, "A")

    @mock.patch.object(security, "scan_host", side_effect=lambda host: facts(hostname=host))
    def test_scheduled_scan_is_idempotent(self, scan):
        self.assertTrue(security.scheduled_scan().startswith("scanned 2 domain(s), 2 graded"))
        self.assertEqual(sorted(c.args[0] for c in scan.call_args_list), ["a.example.com", "b.example.com"])
        self.assertTrue(security.scheduled_scan().startswith("scanned 0 domain(s)"))   # nothing due within 24 h
        DomainSecurityScan.objects.filter(domain=self.b).update(scanned_at=timezone.now() - timedelta(hours=25))
        self.assertTrue(security.scheduled_scan().startswith("scanned 1 domain(s)"))

    @mock.patch.object(security, "scan_host", side_effect=RuntimeError("boom"))
    def test_unexpected_scan_error_is_recorded_not_raised(self, _scan):
        with self.assertLogs("linkedeye.domains.security", "ERROR"):
            self.assertTrue(security.scheduled_scan().startswith("scanned 2 domain(s), 0 graded"))
        self.assertIn("RuntimeError: boom", DomainSecurityScan.objects.first().error)

    @mock.patch.object(security, "due_domains", side_effect=RuntimeError("db gone"))
    def test_scheduled_scan_never_raises(self, _due):
        with self.assertLogs("linkedeye.domains.security", "ERROR"):
            self.assertEqual(security.scheduled_scan(), "error")

    def test_prune_keeps_latest_scan(self):
        old = timezone.now() - timedelta(days=security.RETENTION_DAYS + 5)
        s_old = security.save_scan(self.a, facts(), now=old - timedelta(days=1))
        s_latest_b = security.save_scan(self.b, facts(), now=old)   # old, but the only scan of b
        s_new = security.save_scan(self.a, facts())
        self.assertEqual(security.prune(), 1)
        self.assertFalse(DomainSecurityScan.objects.filter(pk=s_old.pk).exists())
        self.assertTrue(DomainSecurityScan.objects.filter(pk__in=[s_latest_b.pk, s_new.pk]).count() == 2)


class AnalyticsTests(TestCase):
    def setUp(self):
        self.d = Domain.objects.create(tenant_key="default", hostname="a.example.com")
        self.now = timezone.now().replace(microsecond=0)

    def add(self, minutes_ago, up, ms=None, message=""):
        return DomainCheck.objects.create(domain=self.d, checked_at=self.now - timedelta(minutes=minutes_ago), up=up,
                                          response_ms=ms, dns_status="Resolved", ssl_status="Valid", message=message)

    def test_percentiles(self):
        self.assertEqual(analytics.percentile([1, 2, 3, 4], 50), 2.5)
        self.assertAlmostEqual(analytics.percentile([1, 2, 3, 4], 95), 3.85)
        self.assertEqual(analytics.percentile([7], 95), 7)
        self.assertIsNone(analytics.percentile([], 50))
        d = analytics.describe([300, 100, 200])
        self.assertEqual((d["n"], d["p50"], d["max"], d["avg"]), (3, 200, 300, 200))

    def test_downtime_periods(self):
        self.add(60, True, 100)
        self.add(50, False, message="Connection refused")
        self.add(40, False)
        self.add(30, True, 100)    # recovers: period 50 → 30 min ago
        self.add(20, True, 100)
        self.add(10, False, message="HTTP 503")   # still down
        periods = analytics.downtime_periods([self.d.pk], self.now - timedelta(hours=2), self.now)
        self.assertEqual(len(periods), 2)
        ongoing, done = periods
        self.assertTrue(ongoing["ongoing"])
        self.assertEqual(ongoing["duration"], timedelta(minutes=10))
        self.assertEqual((done["failed"], done["duration"], done["message"]), (2, timedelta(minutes=20), "Connection refused"))
        s = analytics.summarize_periods(periods)[self.d.pk]
        self.assertEqual((s["count"], s["total"], s["longest"]), (2, timedelta(minutes=30), timedelta(minutes=20)))
        self.assertEqual(analytics.fmt_duration(timedelta(hours=3, minutes=5)), "3h 05m")
        self.assertEqual(analytics.fmt_duration(timedelta(days=2, hours=4)), "2d 4h")

    def test_uptime_windows_and_daily(self):
        self.add(30, True)
        self.add(20, False)
        self.add(60 * 24 * 3, True)
        self.add(60 * 24 * 40, False)   # outside every window
        w = analytics.uptime_windows([self.d.pk], self.now)[self.d.pk]
        self.assertEqual((w["24h"], round(w["7d"], 2), w["checks_30d"]), (50.0, 66.67, 3))
        dates, overall, per = analytics.daily_availability([self.d.pk], 7)
        self.assertEqual(len(dates), 7)
        self.assertEqual(sum(c["n"] for c in per[self.d.pk]), 3)
        self.assertEqual(overall.count(None), 7 - len({c["date"] for c in per[self.d.pk] if c["n"]}))
