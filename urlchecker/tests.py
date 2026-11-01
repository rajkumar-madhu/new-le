from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from probes import checks

from . import stats
from .forms import UrlCheckForm
from .models import UrlCheck, UrlResult


def ok_result():
    return checks.HttpResult(ok=True, status=200, response_ms=100.0, ip="93.184.216.34", error="")


class UrlCheckerPageTests(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user("op", password="x" * 14, is_staff=True)
        self.viewer = User.objects.create_user("viewer", password="x" * 14)
        self.a = UrlCheck.objects.create(name="Alpha", url="https://a.example.com/", last_status="online")
        self.b = UrlCheck.objects.create(name="Beta", url="https://b.example.com/", last_status="down")
        now = timezone.now()
        # last 24h averages 200 ms, the 24h before averages 400 ms -> -50 %
        for i in range(4):
            UrlResult.objects.create(url_check=self.a, checked_at=now - timedelta(hours=1 + i), status="online",
                                     http_status=200, response_ms=200, message="200 OK")
            UrlResult.objects.create(url_check=self.a, checked_at=now - timedelta(hours=30 + i), status="online",
                                     http_status=200, response_ms=400, message="200 OK")
        UrlResult.objects.create(url_check=self.b, checked_at=now - timedelta(minutes=5), status="down",
                                 message="Connection refused")

    def test_avg_response_windows(self):
        self.assertAlmostEqual(stats.avg_response([self.a.pk]), 200)
        self.assertAlmostEqual(stats.avg_response([self.a.pk], hours=24, offset_hours=24), 400)

    def test_index_layout_and_computed_kpis(self):
        self.client.force_login(self.staff)
        r = self.client.get(reverse("urlchecker:index"))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.context["avg_delta"], -50)
        self.assertIsNone(r.context["total_delta"])  # nothing existed 7 days ago to compare with
        html = r.content.decode()
        for text in ("Add / Edit URL Check", "Follow Redirects", "Advanced options", "data-check-all", "View All",
                     "<th>Message</th>", "Connection refused", "of 2 URLs", "linkedeye/pages/urlchecker.css"):
            self.assertIn(text, html)
        self.assertEqual(r.context["history"]["xLabelEvery"], 1)
        self.assertEqual(len(r.context["events"]), 6)

    def test_total_delta_uses_created_at(self):
        UrlCheck.objects.filter(pk=self.a.pk).update(created_at=timezone.now() - timedelta(days=10))
        self.client.force_login(self.staff)
        r = self.client.get(reverse("urlchecker:index"))
        self.assertEqual(r.context["total_delta"], 100)  # 1 check a week ago, 2 now

    def test_view_all_events_and_bad_per(self):
        self.client.force_login(self.viewer)
        r = self.client.get(reverse("urlchecker:index") + "?events=all&per=abc")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.context["events"]), 9)
        self.assertEqual(r.context["page"].paginator.per_page, 10)
        self.assertNotIn("Save URL", r.content.decode())  # viewers do not get the form

    def test_form_keeps_custom_expected_status(self):
        check = UrlCheck.objects.create(name="Odd", url="https://odd.example.com/", expected_status=418)
        form = UrlCheckForm(instance=check)
        self.assertIn((418, "418"), form.fields["expected_status"].widget.choices)
        self.assertIn(("web", "HTTP/HTTPS"), list(form.fields["check_type"].choices))
        self.assertEqual(form["url"].label, "URL")

    def test_advanced_fields_still_submit(self):
        self.client.force_login(self.staff)
        data = {"name": "G", "url": "https://g.example.com/", "check_type": "api", "method": "GET", "expected_status": 204,
                "interval_seconds": 60, "site": "Mumbai", "degraded_ms": 750, "timeout_seconds": 5, "enabled": "on",
                "follow_redirects": "on"}
        with mock.patch.object(checks, "http_check", return_value=ok_result()):
            r = self.client.post(reverse("urlchecker:index"), data)
        self.assertEqual(r.status_code, 302)
        g = UrlCheck.objects.get(name="G")
        self.assertEqual((g.degraded_ms, g.timeout_seconds, g.expected_status), (750, 5, 204))

    def test_advanced_section_opens_on_error(self):
        self.client.force_login(self.staff)
        r = self.client.post(reverse("urlchecker:index"), {"name": "H", "url": "https://h.example.com/", "check_type": "web",
                                                           "method": "GET", "expected_status": 200, "interval_seconds": 300,
                                                           "site": "s", "degraded_ms": "", "timeout_seconds": 10})
        self.assertEqual(r.status_code, 200)
        self.assertIn('class="field full advanced" open', r.content.decode())

    def test_delete_from_row_menu(self):
        self.client.force_login(self.staff)
        r = self.client.post(reverse("urlchecker:delete", args=[self.b.pk]))
        self.assertEqual(r.status_code, 302)
        self.assertFalse(UrlCheck.objects.filter(pk=self.b.pk).exists())

    def test_detail_renders(self):
        self.client.force_login(self.viewer)
        r = self.client.get(reverse("urlchecker:detail", args=[self.a.pk]))
        self.assertEqual(r.status_code, 200)
        self.assertIn("Check History", r.content.decode())

    def test_axis_scale_is_tight(self):
        self.assertEqual(stats.axis_scale(2600), {"yMax": 3000, "yTicks": 3})
        self.assertEqual(stats.axis_scale(42), {"yMax": 50, "yTicks": 5})
        self.assertEqual(stats.axis_scale(0), {})
