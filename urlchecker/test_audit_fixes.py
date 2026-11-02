"""Regression tests for the URL Checker audit findings (site scoping, per-site roles, duplicate names, DB aggregation)."""
from datetime import datetime, time, timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils import timezone

from core.models import Membership, Site
from probes import checks

from . import stats
from .models import UrlCheck, UrlResult


def ok_result():
    return checks.HttpResult(ok=True, status=200, response_ms=100.0, ip="93.184.216.34", error="")


FORM = {"url": "https://c.example.com/", "check_type": "web", "method": "GET", "expected_status": 200,
        "interval_seconds": 300, "degraded_ms": 1000, "timeout_seconds": 10, "enabled": "on"}


def user_with(name, role, site=None, **extra):
    u = User.objects.create_user(name, password="x" * 14, **extra)
    Membership.objects.create(user=u, site=site, role=role)
    return u


class SiteScopingTests(TestCase):
    def setUp(self):
        self.site_a = Site.objects.create(name="SiteA", code="site-a")
        self.site_b = Site.objects.create(name="SiteB", code="site-b")
        self.viewer = user_with("v", "viewer", self.site_a)
        self.ok_a = UrlCheck.objects.create(name="ok-a", url="https://a.example.com/", site="SiteA", last_status="online")
        self.glob = UrlCheck.objects.create(name="global", url="https://g.example.com/", site="All Sites")
        self.secret = UrlCheck.objects.create(name="secret-b", url="https://b.internal/", site="SiteB",
                                              last_status="down", last_error="conn refused b-db-01")
        UrlResult.objects.create(url_check=self.secret, checked_at=timezone.now(), status="down", message="b-only-event")
        self.client.force_login(self.viewer)

    def test_detail_of_other_site_is_hidden(self):
        self.assertEqual(self.client.get(reverse("urlchecker:detail", args=[self.secret.pk])).status_code, 404)
        self.assertEqual(self.client.get(reverse("urlchecker:detail", args=[self.ok_a.pk])).status_code, 200)

    def test_export_excludes_other_site(self):
        body = self.client.get(reverse("urlchecker:export")).content.decode()
        self.assertNotIn("b.internal", body)
        self.assertIn("ok-a", body)
        self.assertIn("global", body)  # "All Sites" checks stay visible

    def test_index_list_kpis_events_and_site_filter_are_scoped(self):
        r = self.client.get(reverse("urlchecker:index"))
        self.assertEqual(r.status_code, 200)
        html = r.content.decode()
        self.assertNotIn("secret-b", html)
        self.assertNotIn("b-only-event", html)
        self.assertEqual(r.context["total"], 2)
        self.assertEqual([c.name for c in r.context["page"]], ["global", "ok-a"])
        self.assertNotIn("SiteB", list(r.context["sites"]))
        self.assertFalse(any(e.url_check_id == self.secret.pk for e in r.context["events"]))

    def test_unrestricted_user_still_sees_everything(self):
        self.client.force_login(user_with("all", "viewer"))
        r = self.client.get(reverse("urlchecker:index"))
        self.assertEqual(r.context["total"], 3)
        self.assertIn("SiteB", list(r.context["sites"]))


class PerSiteRoleTests(TestCase):
    def setUp(self):
        self.site_a = Site.objects.create(name="SiteA", code="site-a")
        self.site_b = Site.objects.create(name="SiteB", code="site-b")
        self.b_check = UrlCheck.objects.create(name="B-check", url="https://b.example.com/", site="SiteB")
        UrlResult.objects.create(url_check=self.b_check, checked_at=timezone.now(), status="online")
        self.a_check = UrlCheck.objects.create(name="A-check", url="https://a.example.com/", site="SiteA")
        patcher = mock.patch.object(checks, "http_check", return_value=ok_result())
        self.probe = patcher.start()
        self.addCleanup(patcher.stop)

    def test_staff_viewer_cannot_run_edit_or_delete(self):
        u = user_with("sv", "viewer", self.site_b, is_staff=True)
        self.client.force_login(u)
        r = self.client.post(reverse("urlchecker:run", args=[self.b_check.pk]), HTTP_X_CSRFTOKEN="t")
        self.assertEqual(r.status_code, 403)
        self.client.post(reverse("urlchecker:edit", args=[self.b_check.pk]),
                         {**FORM, "name": "B-hijacked", "url": "https://evil.example.com/", "site": "SiteB"})
        self.b_check.refresh_from_db()
        self.assertEqual(self.b_check.name, "B-check")
        self.client.post(reverse("urlchecker:delete", args=[self.b_check.pk]))
        self.assertTrue(UrlCheck.objects.filter(pk=self.b_check.pk).exists())
        self.assertEqual(self.b_check.results.count(), 1)
        self.probe.assert_not_called()

    def test_operator_of_other_site_cannot_touch_site_b(self):
        u = user_with("opa", "operator", self.site_a)
        Membership.objects.create(user=u, site=self.site_b, role="viewer")
        self.client.force_login(u)
        r = self.client.post(reverse("urlchecker:run", args=[self.b_check.pk]), HTTP_X_CSRFTOKEN="t")
        self.assertEqual(r.status_code, 403)
        r = self.client.post(reverse("urlchecker:edit", args=[self.b_check.pk]), {**FORM, "name": "X", "site": "SiteB"})
        self.b_check.refresh_from_db()
        self.assertEqual(self.b_check.name, "B-check")
        # cannot move its own check to a site it only views, nor create one there
        r = self.client.post(reverse("urlchecker:edit", args=[self.a_check.pk]), {**FORM, "name": "A-check", "site": "SiteB"})
        self.assertEqual(r.status_code, 200)
        self.a_check.refresh_from_db()
        self.assertEqual(self.a_check.site, "SiteA")
        r = self.client.post(reverse("urlchecker:index"), {**FORM, "name": "new-b", "site": "SiteB"})
        self.assertFalse(UrlCheck.objects.filter(name="new-b").exists())
        # run all only runs what the user may operate
        r = self.client.post(reverse("urlchecker:run_all"), HTTP_X_CSRFTOKEN="t")
        self.assertEqual(r.json()["checked"], 1)
        # its own site works
        r = self.client.post(reverse("urlchecker:index"), {**FORM, "name": "new-a", "site": "SiteA"})
        self.assertEqual(r.status_code, 302)
        self.assertTrue(UrlCheck.objects.filter(name="new-a", site="SiteA").exists())

    def test_operator_cannot_delete_but_admin_can(self):
        op = user_with("opb", "operator", self.site_b)
        self.client.force_login(op)
        self.client.post(reverse("urlchecker:delete", args=[self.b_check.pk]))
        self.assertTrue(UrlCheck.objects.filter(pk=self.b_check.pk).exists())
        admin_b = user_with("adb", "admin", self.site_b)
        self.client.force_login(admin_b)
        self.client.post(reverse("urlchecker:delete", args=[self.b_check.pk]))
        self.assertFalse(UrlCheck.objects.filter(pk=self.b_check.pk).exists())

    def test_non_staff_tenant_admin_can_add_run_and_delete(self):
        u = user_with("ta", "admin")  # site=None: admin on every site, not staff
        self.client.force_login(u)
        r = self.client.post(reverse("urlchecker:index"), {**FORM, "name": "new", "site": "SiteB"})
        self.assertEqual(r.status_code, 302)
        self.assertTrue(UrlCheck.objects.filter(name="new").exists())
        r = self.client.post(reverse("urlchecker:run", args=[self.b_check.pk]), HTTP_X_CSRFTOKEN="t")
        self.assertEqual(r.status_code, 200)
        self.client.post(reverse("urlchecker:delete", args=[self.b_check.pk]))
        self.assertFalse(UrlCheck.objects.filter(pk=self.b_check.pk).exists())

    def test_templates_hide_controls_by_role(self):
        u = user_with("opa2", "operator", self.site_a)
        Membership.objects.create(user=u, site=self.site_b, role="viewer")
        self.client.force_login(u)
        html = self.client.get(reverse("urlchecker:index")).content.decode()
        self.assertIn(reverse("urlchecker:edit", args=[self.a_check.pk]), html)
        self.assertNotIn(reverse("urlchecker:edit", args=[self.b_check.pk]), html)
        self.assertNotIn(reverse("urlchecker:run", args=[self.b_check.pk]), html)
        self.assertNotIn(reverse("urlchecker:delete", args=[self.a_check.pk]), html)  # operator: no delete
        self.assertIn("Save URL", html)
        detail_b = self.client.get(reverse("urlchecker:detail", args=[self.b_check.pk])).content.decode()
        self.assertNotIn(reverse("urlchecker:run", args=[self.b_check.pk]), detail_b)
        detail_a = self.client.get(reverse("urlchecker:detail", args=[self.a_check.pk])).content.decode()
        self.assertIn(reverse("urlchecker:run", args=[self.a_check.pk]), detail_a)
        # a site-B viewer gets no add form, and an edit link to a B check does not open it
        self.client.force_login(user_with("vb", "viewer", self.site_b, is_staff=True))
        html = self.client.get(reverse("urlchecker:edit", args=[self.b_check.pk])).content.decode()
        self.assertNotIn("Save URL", html)
        self.assertNotIn("Save changes", html)
        self.assertNotIn(reverse("urlchecker:run_all"), html)


class DuplicateNameTests(TestCase):
    def setUp(self):
        self.client.raise_request_exception = False
        self.client.force_login(User.objects.create_user("op", password="x" * 14, is_staff=True))
        self.alpha = UrlCheck.objects.create(name="Alpha", url="https://a.example.com/")
        self.beta = UrlCheck.objects.create(name="Beta", url="https://b.example.com/")

    def test_add_duplicate_name_is_a_form_error(self):
        with mock.patch.object(checks, "http_check", return_value=ok_result()):
            r = self.client.post(reverse("urlchecker:index"), {**FORM, "name": "Alpha", "site": "All Sites"})
        self.assertEqual(r.status_code, 200)
        self.assertIn("already", r.content.decode())
        self.assertEqual(UrlCheck.objects.filter(name="Alpha").count(), 1)

    def test_rename_to_taken_name_is_a_form_error(self):
        with mock.patch.object(checks, "http_check", return_value=ok_result()):
            r = self.client.post(reverse("urlchecker:edit", args=[self.beta.pk]), {**FORM, "name": "Alpha", "site": "All Sites"})
        self.assertEqual(r.status_code, 200)
        self.beta.refresh_from_db()
        self.assertEqual(self.beta.name, "Beta")

    def test_saving_with_own_name_still_works(self):
        with mock.patch.object(checks, "http_check", return_value=ok_result()):
            r = self.client.post(reverse("urlchecker:edit", args=[self.beta.pk]), {**FORM, "name": "Beta", "site": "All Sites"})
        self.assertEqual(r.status_code, 302)


class AggregationTests(TestCase):
    def setUp(self):
        self.a = UrlCheck.objects.create(name="A", url="https://a.example.com/")
        self.b = UrlCheck.objects.create(name="B", url="https://b.example.com/")
        today = timezone.localdate()
        noon = lambda d: timezone.make_aware(datetime.combine(d, time(12)))  # noqa: E731
        rows = []
        # today: A all online (20 results), B 2/20 down (>5%) -> 1 online, 1 down
        for i in range(20):
            rows.append(UrlResult(url_check=self.a, checked_at=noon(today) - timedelta(minutes=i), status="online"))
            rows.append(UrlResult(url_check=self.b, checked_at=noon(today) - timedelta(minutes=i),
                                  status="down" if i < 2 else "online"))
        # yesterday: A 1/20 degraded (=5%, not >5%) -> online; B 3/20 degraded -> degraded
        y = today - timedelta(days=1)
        for i in range(20):
            rows.append(UrlResult(url_check=self.a, checked_at=noon(y) - timedelta(minutes=i), status="degraded" if i < 1 else "online"))
            rows.append(UrlResult(url_check=self.b, checked_at=noon(y) - timedelta(minutes=i), status="degraded" if i < 3 else "online"))
        # a result just after local midnight 6 days ago counts; one just before is outside the window
        start = today - timedelta(days=6)
        rows.append(UrlResult(url_check=self.a, checked_at=timezone.make_aware(datetime.combine(start, time(0, 1))), status="down"))
        rows.append(UrlResult(url_check=self.b, checked_at=timezone.make_aware(datetime.combine(start, time(0, 0))) - timedelta(minutes=1), status="down"))
        # response trend data
        now = timezone.now()
        for i, ms in enumerate((100, 300, 200)):
            rows.append(UrlResult(url_check=self.a, checked_at=now - timedelta(minutes=5 + i), status="online", response_ms=ms))
        rows.append(UrlResult(url_check=self.b, checked_at=now - timedelta(hours=3, minutes=1), status="online", response_ms=50))
        rows.append(UrlResult(url_check=self.b, checked_at=now - timedelta(hours=30), status="online", response_ms=9999))
        UrlResult.objects.bulk_create(rows)

    def test_daily_history_classification(self):
        h = stats.daily_history([self.a, self.b])
        series = {s["name"]: s["values"] for s in h["series"]}
        self.assertEqual(len(h["labels"]), 7)
        self.assertEqual((series["Online"][-1], series["Down"][-1], series["Degraded"][-1]), (1, 1, None))
        self.assertEqual((series["Online"][-2], series["Down"][-2], series["Degraded"][-2]), (1, None, 1))
        self.assertEqual((series["Online"][0], series["Down"][0], series["Degraded"][0]), (None, 1, None))

    def test_response_trend_buckets(self):
        t = stats.response_trend([self.a, self.b])
        avg, mn, mx = (s["values"] for s in t["series"])
        self.assertEqual(len(avg), 48)
        self.assertEqual((avg[-1], mn[-1], mx[-1]), (200.0, 100, 300))
        # 3h01m ago falls in the 7th bucket from the end (30-minute buckets)
        self.assertEqual((avg[-7], mn[-7], mx[-7]), (50.0, 50, 50))
        self.assertEqual(sum(1 for v in avg if v is not None), 2)
        self.assertEqual(t["yMax"], 300)

    def test_aggregation_happens_in_the_database(self):
        """The index must not stream every raw result row to Python: both queries return aggregates only."""
        for fn in (stats.daily_history, stats.response_trend):
            with CaptureQueriesContext(connection) as ctx:
                fn([self.a, self.b])
            sql = " ".join(q["sql"] for q in ctx.captured_queries).upper()
            self.assertTrue("COUNT(" in sql or "AVG(" in sql, f"{fn.__name__} fetched raw rows: {sql}")
