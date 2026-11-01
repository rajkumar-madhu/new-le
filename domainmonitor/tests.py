import csv
import io
from datetime import timedelta

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from urlchecker.models import UrlCheck

from .models import Domain, DomainCheck
from .views import associated_services


class DomainPagesTests(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user("op", password="x" * 14, is_staff=True)
        self.viewer = User.objects.create_user("viewer", password="x" * 14)
        now = timezone.now()
        self.up = Domain.objects.create(tenant_key="default", site_key="Mumbai", hostname="example.com", status="up",
                                        dns_status="Resolved", ssl_status="Valid", ip_address="10.0.0.1", response_ms=200,
                                        last_checked_at=now)
        self.down = Domain.objects.create(tenant_key="default", site_key="DR", hostname="down.example.org", status="down",
                                          dns_status="Failed", ssl_status="Expired", domain_type="Mail")
        for i in range(4):
            DomainCheck.objects.create(domain=self.up, checked_at=now - timedelta(hours=i), up=True, response_ms=100 + i,
                                       ip_address="10.0.0.1" if i else "10.0.0.2", dns_status="Resolved", ssl_status="Valid")
        DomainCheck.objects.create(domain=self.down, checked_at=now - timedelta(hours=1), up=False, dns_status="Failed",
                                   ssl_status="Expired")

    def test_pages_render_for_staff_and_viewer(self):
        for user in (self.staff, self.viewer):
            self.client.force_login(user)
            for url in (reverse("domains:overview"), reverse("domains:list"), reverse("domains:ssl"), reverse("domains:dns"),
                        reverse("domains:list") + f"?selected={self.up.pk}&dtab=history",
                        reverse("domains:overview") + "?resp_range=168&up_range=30&sort=-status&per=5",
                        reverse("domains:overview") + "?resp_range=bogus&sort=bogus&per=x"):
                self.assertEqual(self.client.get(url).status_code, 200, url)

    def test_empty_database_renders(self):
        Domain.objects.all().delete()
        self.client.force_login(self.staff)
        for name in ("domains:overview", "domains:list", "domains:dns", "domains:ssl"):
            self.assertEqual(self.client.get(reverse(name)).status_code, 200, name)

    def test_overview_counts_come_from_records(self):
        self.client.force_login(self.staff)
        r = self.client.get(reverse("domains:overview"))
        self.assertEqual(r.context["total"], 2)
        self.assertEqual(r.context["n"]["healthy"], 1)
        self.assertEqual(r.context["n"]["down"], 1)
        self.assertEqual(r.context["n"]["expiring"], 1)
        self.assertIsNone(r.context["trend"]["total"])  # no domains existed a week ago
        values = [v for v in r.context["resp"]["series"][0]["values"] if v is not None]
        self.assertTrue(values)
        self.assertContains(r, "Uptime &amp; Availability")

    def test_filters_and_sort(self):
        self.client.force_login(self.staff)
        r = self.client.get(reverse("domains:overview") + "?status=down")
        self.assertEqual([d.hostname for d in r.context["page"]], ["down.example.org"])
        r = self.client.get(reverse("domains:list") + "?dns=Failed")
        self.assertEqual([d.hostname for d in r.context["page"]], ["down.example.org"])
        r = self.client.get(reverse("domains:list") + "?ssl=Valid&type=Production")
        self.assertEqual([d.hostname for d in r.context["page"]], ["example.com"])

    def test_csv_export(self):
        self.client.force_login(self.viewer)
        for url in (reverse("domains:export") + "?status=up", reverse("domains:overview") + "?status=up&format=csv"):
            r = self.client.get(url)
            self.assertEqual(r["Content-Type"], "text/csv")
            rows = list(csv.reader(io.StringIO(r.content.decode())))
            self.assertEqual(rows[0][0], "hostname")
            self.assertEqual([row[0] for row in rows[1:]], ["example.com"])

    def test_detail_panel_uses_real_records(self):
        UrlCheck.objects.create(name="Portal", url="https://www.example.com:8443/login", last_status="online")
        UrlCheck.objects.create(name="Root", url="http://example.com/")
        UrlCheck.objects.create(name="Other", url="https://notexample.com/")
        UrlCheck.objects.create(name="Path only", url="https://other.net/example.com")
        self.client.force_login(self.staff)
        r = self.client.get(reverse("domains:list") + f"?selected={self.up.pk}")
        services = {s.name: s.port for s in r.context["services"]}
        self.assertEqual(services, {"Portal": 8443, "Root": 80})
        self.assertEqual({row["ip"] for row in r.context["dns_records"]}, {"10.0.0.1", "10.0.0.2"})
        self.assertEqual(len(r.context["recent"]), 4)
        self.assertContains(r, "Associated Services (2)")
        self.assertEqual(len(associated_services(self.down)), 0)

    def test_list_kpis(self):
        self.client.force_login(self.staff)
        k = self.client.get(reverse("domains:list")).context["k"]
        self.assertEqual((k["total"], k["active"], k["expiring"], k["dns"]), (2, 2, 1, 1))
        self.assertEqual(k["active_pct"], 100.0)
        self.assertEqual(k["dns_pct"], 50.0)

    def test_viewer_sees_no_operator_buttons(self):
        self.client.force_login(self.viewer)
        r = self.client.get(reverse("domains:overview"))
        self.assertNotContains(r, reverse("domains:run_all"))
        self.assertNotContains(r, "Add Domain")

    def test_donut_counts_each_domain_once(self):
        Domain.objects.create(tenant_key="default", hostname="soon.example.net", status="up", dns_status="Resolved",
                              ssl_status="Expiring")
        self.client.force_login(self.staff)
        r = self.client.get(reverse("domains:overview"))
        slices = {x["label"]: x["n"] for x in r.context["legend"]}
        # down.example.org is down and has an expired certificate: it is counted as Down only
        self.assertEqual(slices, {"Healthy": 1, "Down": 1, "SSL Expiring": 1, "Paused": 0})
        self.assertEqual(sum(slices.values()), r.context["total"])
        self.assertEqual(r.context["n"]["expiring"], 2)  # the KPI card still counts every expiring certificate

    def test_list_opens_page_of_selected_domain(self):
        for i in range(12):
            Domain.objects.create(tenant_key="default", hostname=f"a{i:02d}.example.net")
        last = Domain.objects.create(tenant_key="default", hostname="zz.example.net")
        self.client.force_login(self.staff)
        r = self.client.get(reverse("domains:list") + f"?selected={last.pk}&per=5")
        self.assertIn(last, list(r.context["page"]))
        self.assertEqual(r.context["selected"], last)
        self.assertEqual(self.client.get(reverse("domains:list") + "?selected=abc").status_code, 200)
        self.assertEqual(self.client.get(reverse("domains:list") + "?edit=abc").status_code, 404)
