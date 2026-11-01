import json
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from domainmonitor.models import Domain, DomainCheck
from probes import checks, runner
from urlchecker.models import UrlCheck, UrlResult


def fake_http(status=200, ms=120.0, ok=True, error=""):
    return checks.HttpResult(ok=ok, status=status if ok else None, response_ms=ms, ip="93.184.216.34", error=error)


class HostnameValidationTests(TestCase):
    def test_real_hostnames_validate(self):
        # The original patch's regex rejected these.
        for h in ("nse.finspot.in", "a-b.example.co.in", "example.com"):
            Domain(tenant_key="t", site_key="s", hostname=h).full_clean()

    def test_bad_hostnames_rejected(self):
        from django.core.exceptions import ValidationError
        for h in ("-bad.example.com", "nodot", "a..b.com", "http://x.com"):
            with self.assertRaises(ValidationError, msg=h):
                Domain(tenant_key="t", site_key="s", hostname=h).full_clean()


class RunnerTests(TestCase):
    def setUp(self):
        self.check = UrlCheck.objects.create(name="Site", url="https://example.com/", degraded_ms=500)

    def run_with(self, result):
        with mock.patch.object(checks, "http_check", return_value=result):
            return runner.run_url_checks([self.check])[0]

    def test_online(self):
        self.assertEqual(self.run_with(fake_http()), "online")
        self.check.refresh_from_db()
        self.assertEqual(self.check.last_http_status, 200)
        self.assertEqual(UrlResult.objects.count(), 1)

    def test_slow_is_degraded(self):
        self.assertEqual(self.run_with(fake_http(ms=900)), "degraded")

    def test_wrong_status_is_down(self):
        self.assertEqual(self.run_with(fake_http(status=503)), "down")
        self.check.refresh_from_db()
        self.assertIn("expected 200", self.check.last_error)

    def test_transport_error_is_down_without_response_time(self):
        self.assertEqual(self.run_with(fake_http(ok=False, error="Timed out after 10s")), "down")
        self.assertIsNone(UrlResult.objects.get().response_ms)

    def test_due_logic(self):
        self.assertTrue(self.check.is_due())
        self.run_with(fake_http())
        self.check.refresh_from_db()
        self.assertFalse(self.check.is_due())

    def test_domain_check(self):
        d = Domain.objects.create(tenant_key="default", site_key="s", hostname="example.com")
        tls = checks.TlsResult("Valid", timezone.now() + timezone.timedelta(days=60), 60)
        with mock.patch.object(checks, "dns_check", return_value=checks.DnsResult(True, ["93.184.216.34"])), \
             mock.patch.object(checks, "http_check", return_value=fake_http()), \
             mock.patch.object(checks, "tls_check", return_value=tls):
            runner.run_domain_checks([d])
        d.refresh_from_db()
        self.assertEqual((d.status, d.dns_status, d.ssl_status, d.ip_address), ("up", "Resolved", "Valid", "93.184.216.34"))
        self.assertEqual(DomainCheck.objects.count(), 1)

    def test_domain_dns_failure(self):
        d = Domain.objects.create(tenant_key="default", site_key="s", hostname="nx.example.com")
        with mock.patch.object(checks, "dns_check", return_value=checks.DnsResult(False, [], "DNS resolution failed")):
            runner.run_domain_checks([d])
        d.refresh_from_db()
        self.assertEqual((d.status, d.dns_status), ("down", "Failed"))


class ViewTests(TestCase):
    def setUp(self):
        self.viewer = User.objects.create_user("viewer", password="x" * 14)
        self.staff = User.objects.create_user("op", password="x" * 14, is_staff=True)

    def test_login_required(self):
        self.assertEqual(self.client.get(reverse("urlchecker:index")).status_code, 302)
        self.assertEqual(self.client.get("/configuration/domains/api/?tenant=default").status_code, 401)
        self.assertEqual(self.client.get("/healthz").status_code, 200)

    def test_every_page_renders(self):
        self.client.force_login(self.staff)
        UrlCheck.objects.create(name="A", url="https://example.com/")
        Domain.objects.create(tenant_key="default", site_key="s", hostname="example.com")
        for name in ("dashboard", "urlchecker:index", "domains:overview", "domains:list", "domains:ssl",
                     "heatmap", "exporters", "incidents", "firewall"):
            self.assertEqual(self.client.get(reverse(name)).status_code, 200, name)
        self.assertEqual(self.client.get(reverse("coming_soon", args=["switches"])).status_code, 200)
        self.assertEqual(self.client.get(reverse("search") + "?q=exa").status_code, 200)

    def test_viewer_cannot_create(self):
        self.client.force_login(self.viewer)
        self.client.post(reverse("urlchecker:index"), {"name": "X", "url": "https://x.com/"})
        self.assertFalse(UrlCheck.objects.exists())

    def test_staff_creates_url_check_and_first_check_runs(self):
        self.client.force_login(self.staff)
        data = {"name": "X", "url": "https://x.example.com/", "check_type": "web", "method": "GET", "expected_status": 200,
                "interval_seconds": 300, "site": "All Sites", "degraded_ms": 1000, "timeout_seconds": 10, "enabled": "on"}
        with mock.patch.object(checks, "http_check", return_value=fake_http()):
            r = self.client.post(reverse("urlchecker:index"), data)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(UrlCheck.objects.get().last_status, "online")

    def test_rejects_non_http_scheme(self):
        self.client.force_login(self.staff)
        r = self.client.post(reverse("urlchecker:index"), {"name": "X", "url": "ftp://x.com/", "check_type": "web", "method": "GET",
                                                           "expected_status": 200, "interval_seconds": 300, "site": "s",
                                                           "degraded_ms": 1000, "timeout_seconds": 10})
        self.assertEqual(r.status_code, 200)
        self.assertFalse(UrlCheck.objects.exists())

    def test_patch_api_contract(self):
        self.client.force_login(self.staff)
        r = self.client.post("/configuration/domains/api/", json.dumps({"tenant": "default", "site": "mum", "hostname": "NSE.Finspot.in."}),
                             content_type="application/json")
        self.assertEqual(r.status_code, 201, r.content)
        r = self.client.get("/configuration/domains/api/?tenant=default")
        self.assertEqual(r.json()["results"][0]["hostname"], "nse.finspot.in")
        self.assertEqual(self.client.get("/configuration/domains/api/").status_code, 400)
        pk = r.json()["results"][0]["id"]
        self.assertEqual(self.client.delete(f"/configuration/domains/api/{pk}/?tenant=default").json()["status"], "deactivated")
