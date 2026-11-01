import json
import threading
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from io import StringIO
from unittest import mock

from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.db import IntegrityError
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from core import jobs as core_jobs
from core.events import emit
from core.models import AuditEvent, Event, Membership, Site

from . import jobs, scrape, services
from .models import Exporter, ExporterStatus, LogEntry
from .scrape import ScrapeResult

T = "default"
TOKEN = "s3cret-token"
INGEST = "/api/v1/logs/"


def exp(name="node-01", **kw):
    kw.setdefault("tenant_key", T)
    kw.setdefault("exporter_type", "Node Exporter")
    kw.setdefault("category", "Servers")
    return Exporter.objects.create(name=name, **kw)


def log(source="app", level="INFO", message="hello", **kw):
    kw.setdefault("tenant_key", T)
    return LogEntry.objects.create(source=source, level=level, message=message, **kw)


def ok(samples=12, ms=4.2):
    return ScrapeResult(ok=True, status=200, response_ms=ms, samples=samples)


def fail(error="Connection refused"):
    return ScrapeResult(ok=False, response_ms=1.0, error=error)


def users():
    viewer = User.objects.create_user("viewer", password="pw")
    operator = User.objects.create_user("operator", password="pw", is_staff=True)
    admin = User.objects.create_superuser("admin", "a@example.com", "pw")
    return viewer, operator, admin


def client_for(user, csrf=False):
    c = Client(enforce_csrf_checks=csrf)
    c.force_login(user)
    return c


# ------------------------------------------------------------------------------------------- local server
METRICS = (b"# HELP up Is it up\n# TYPE up gauge\nup 1\n"
           b'node_cpu_seconds_total{cpu="0",mode="idle"} 12345.6\n'
           b"node_load1 0.42 1700000000000\n\n# EOF\n")


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/metrics":
            body, status, ctype = METRICS, 200, "text/plain"
        elif self.path == "/html":
            body, status, ctype = b"<html><body>Hello world</body></html>", 200, "text/html"
        elif self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/metrics")
            self.end_headers()
            return
        elif self.path == "/metadata":
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.end_headers()
            return
        else:
            body, status, ctype = b"not found", 404, "text/plain"
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class LocalServer:
    def __enter__(self):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


# ------------------------------------------------------------------------------------------- models
@override_settings(LINKEDEYE_TENANT=T)
class ModelTests(TestCase):
    def test_config_status(self):
        e = exp(enabled=False, metrics_url="http://x/metrics")
        self.assertEqual(e.config_status(), ExporterStatus.INACTIVE)
        e.enabled = True
        self.assertIsNone(e.config_status())
        e.metrics_url = ""
        self.assertEqual(e.config_status(), ExporterStatus.NOT_CONFIGURED)
        self.assertFalse(e.scrapeable)

    def test_apply_config_status(self):
        e = exp(metrics_url="http://a/metrics", status=ExporterStatus.ACTIVE, samples=10, last_seen=timezone.now())
        self.assertTrue(e.apply_config_status())
        self.assertEqual(e.status, ExporterStatus.ACTIVE)          # unchanged URL keeps the scrape state
        e.metrics_url = "http://b/metrics"
        self.assertTrue(e.apply_config_status(url_changed=True))
        self.assertEqual(e.status, ExporterStatus.NOT_CONFIGURED)
        self.assertIsNone(e.samples)
        self.assertIsNone(e.last_seen)
        e.enabled = False
        self.assertFalse(e.apply_config_status())
        self.assertEqual(e.status, ExporterStatus.INACTIVE)
        e.enabled, e.metrics_url = True, ""
        self.assertFalse(e.apply_config_status())
        self.assertEqual(e.status, ExporterStatus.NOT_CONFIGURED)
        self.assertEqual(e.last_error, "No metrics URL configured")

    def test_unique_name_per_tenant(self):
        exp("dup")
        exp("dup", tenant_key="other")
        with self.assertRaises(IntegrityError):
            exp("dup")

    def test_category_style_and_log_tone(self):
        e = exp(category="Firewalls")
        self.assertEqual(e.cat_icon, "brick")
        self.assertEqual(log(level="CRITICAL").tone, "crit")
        self.assertEqual(log(level="DEBUG").tone, "mute")


# ------------------------------------------------------------------------------------------- scraping
class ScrapeTests(TestCase):
    def test_count_samples(self):
        lines = [b"# HELP x", b"x 1", b'y{a="b c"} 2 1700', b"", b"<html>", b"Hello world", b"z_total 3"]
        self.assertEqual(scrape.count_samples(lines), 3)

    @override_settings(PROBE_ALLOWED_PRIVATE_CIDRS=["127.0.0.0/8"])
    def test_scrape_local_endpoint(self):
        with LocalServer() as s:
            r = scrape.scrape(s.base + "/metrics", timeout=3)
            self.assertTrue(r.ok, r.error)
            self.assertEqual(r.samples, 3)
            self.assertEqual(r.status, 200)
            r = scrape.scrape(s.base + "/redirect", timeout=3)
            self.assertTrue(r.ok)
            r = scrape.scrape(s.base + "/missing", timeout=3)
            self.assertFalse(r.ok)
            self.assertIn("HTTP 404", r.error)
            r = scrape.scrape(s.base + "/html", timeout=3)
            self.assertFalse(r.ok)
            self.assertIn("No metric samples", r.error)

    @override_settings(PROBE_ALLOWED_PRIVATE_CIDRS=["127.0.0.0/8"])
    def test_redirect_into_metadata_range_is_blocked(self):
        with LocalServer() as s:
            r = scrape.scrape(s.base + "/metadata", timeout=3)
        self.assertFalse(r.ok)
        self.assertIn("Blocked by probe policy", r.error)

    @override_settings(PROBE_ALLOWED_PRIVATE_CIDRS=[])
    def test_loopback_blocked_by_default(self):
        with LocalServer() as s:
            r = scrape.scrape(s.base + "/metrics", timeout=3)
        self.assertFalse(r.ok)
        self.assertIn("Blocked by probe policy", r.error)

    def test_unsupported_scheme(self):
        r = scrape.scrape("ftp://example.com/metrics")
        self.assertFalse(r.ok)
        self.assertIn("unsupported URL", r.error)


# ------------------------------------------------------------------------------------------- health job
@override_settings(LINKEDEYE_TENANT=T, PROBE_WORKERS=1)
class HealthTests(TestCase):
    def test_jobs_registered(self):
        self.assertIn("observe.exporter_health", core_jobs.JOBS)
        self.assertEqual(core_jobs.JOBS["observe.exporter_health"]["interval"], 60)
        self.assertIn("observe.log_retention", core_jobs.JOBS)

    def test_transitions_emit_events(self):
        e = exp(metrics_url="http://10.0.0.1:9100/metrics")
        with mock.patch.object(scrape, "scrape", return_value=ok(42)):
            services.check_exporters([e])
        e.refresh_from_db()
        self.assertEqual((e.status, e.samples), (ExporterStatus.ACTIVE, 42))
        self.assertIsNotNone(e.last_seen)
        self.assertEqual(Event.objects.count(), 0)               # first success is not a state change event

        with mock.patch.object(scrape, "scrape", return_value=fail("Timed out after 10s")):
            services.check_exporters([e])
            services.check_exporters([e])                        # still failing: no second event
        e.refresh_from_db()
        self.assertEqual(e.status, ExporterStatus.ERROR)
        self.assertEqual(e.last_error, "Timed out after 10s")
        ev = Event.objects.get()
        self.assertEqual((ev.source, ev.severity, ev.fingerprint), ("observe", "warning", f"exporter:{e.pk}"))

        with mock.patch.object(scrape, "scrape", return_value=ok(40)):
            services.check_exporters([e])
        self.assertEqual(Event.objects.count(), 2)
        rec = Event.objects.order_by("-id").first()
        self.assertEqual((rec.severity, rec.fingerprint), ("ok", f"exporter:{e.pk}"))

    def test_job_only_scrapes_enabled_with_url_and_syncs_others(self):
        a = exp("a", metrics_url="http://10.0.0.1/metrics")
        b = exp("b", metrics_url="http://10.0.0.2/metrics", enabled=False, status=ExporterStatus.ACTIVE)
        c = exp("c", metrics_url="", status=ExporterStatus.ACTIVE)
        with mock.patch.object(scrape, "scrape", return_value=ok()) as m:
            summary = jobs.exporter_health()
        m.assert_called_once_with("http://10.0.0.1/metrics")
        self.assertIn("1 active", summary)
        for obj, st in ((a, "active"), (b, "inactive"), (c, "not_configured")):
            obj.refresh_from_db()
            self.assertEqual(obj.status, st)

    def test_job_never_raises(self):
        exp(metrics_url="http://10.0.0.1/metrics")
        with mock.patch.object(scrape, "scrape", side_effect=RuntimeError("boom")), \
                self.assertLogs("linkedeye.observe", "ERROR"):
            self.assertIn("1 error", jobs.exporter_health())
        with mock.patch.object(services, "check_exporters", side_effect=RuntimeError("db gone")), \
                self.assertLogs("linkedeye.observe", "ERROR"):
            self.assertEqual(jobs.exporter_health(), "error")


# ------------------------------------------------------------------------------------------- ingest
@override_settings(LINKEDEYE_TENANT=T, LOG_INGEST_TOKEN=TOKEN)
class IngestTests(TestCase):
    def post(self, data, token=TOKEN, ctype="application/json", client=None):
        body = data if isinstance(data, (str, bytes)) else json.dumps(data)
        headers = {"HTTP_AUTHORIZATION": f"Bearer {token}"} if token is not None else {}
        return (client or Client()).post(INGEST, body, content_type=ctype, **headers)

    @override_settings(LOG_INGEST_TOKEN="")
    def test_disabled_without_token(self):
        r = self.post([{"source": "a", "level": "INFO", "message": "m"}], token="")
        self.assertEqual(r.status_code, 503)
        self.assertIn("LINKEDEYE_LOG_INGEST_TOKEN", r.json()["error"])
        self.assertEqual(LogEntry.objects.count(), 0)

    def test_rejects_wrong_or_missing_token(self):
        self.assertEqual(self.post([], token="nope").status_code, 401)
        self.assertEqual(self.post([], token=None).status_code, 401)
        r = Client().post(INGEST, "[]", content_type="application/json", HTTP_AUTHORIZATION=f"Basic {TOKEN}")
        self.assertEqual(r.status_code, 401)
        self.assertEqual(LogEntry.objects.count(), 0)

    def test_get_not_allowed(self):
        r = Client().get(INGEST, HTTP_AUTHORIZATION=f"Bearer {TOKEN}")
        self.assertEqual(r.status_code, 405)

    def test_json_array_without_csrf(self):
        c = Client(enforce_csrf_checks=True)
        r = self.post([{"source": "web", "level": "info", "message": "GET / 200", "host": "web-01", "site": "Mumbai DC",
                        "attributes": {"path": "/"}, "ts": "2026-10-31T10:00:00Z"},
                       {"source": "web", "level": "warning", "message": "slow"}], client=c)
        self.assertEqual(r.status_code, 200, r.content)
        self.assertEqual(r.json()["accepted"], 2)
        e = LogEntry.objects.get(message="GET / 200")
        self.assertEqual((e.level, e.host, e.site, e.attributes), ("INFO", "web-01", "Mumbai DC", {"path": "/"}))
        self.assertEqual(e.ts.isoformat(), "2026-10-31T10:00:00+00:00")
        self.assertEqual(LogEntry.objects.get(message="slow").level, "WARN")

    def test_ndjson_and_single_object(self):
        body = '{"source":"a","level":"INFO","message":"one"}\n\n{"source":"a","level":"ERR","message":"two","ts":1793000000000}\n'
        r = self.post(body, ctype="application/x-ndjson")
        self.assertEqual(r.json()["accepted"], 2)
        self.assertEqual(LogEntry.objects.get(message="two").ts.year, 2026)
        r = self.post({"source": "a", "level": "DEBUG", "message": "single"})
        self.assertEqual(r.json()["accepted"], 1)

    def test_invalid_entries_reported(self):
        r = self.post([{"source": "a", "level": "INFO", "message": "fine"}, {"level": "INFO", "message": "x"},
                       {"source": "a", "level": "LOUD", "message": "x"}, {"source": "a", "level": "INFO"},
                       {"source": "a", "level": "INFO", "message": "x", "ts": "2999-01-01T00:00:00Z"},
                       {"source": "a", "level": "INFO", "message": "x", "attributes": [1]}, "nope"])
        d = r.json()
        self.assertEqual((r.status_code, d["accepted"], d["rejected"]), (200, 1, 6))
        self.assertEqual([e["index"] for e in d["errors"]], [1, 2, 3, 4, 5, 6])
        r = self.post([{"source": "a"}])
        self.assertEqual(r.status_code, 400)

    def test_malformed_and_limits(self):
        self.assertEqual(self.post("[not json").status_code, 400)
        self.assertEqual(self.post("").status_code, 400)
        self.assertEqual(self.post({"a": 1} if False else '"just a string"').status_code, 400)
        many = [{"source": "a", "level": "INFO", "message": "m"}] * 1001
        self.assertEqual(self.post(many).status_code, 413)
        big = [{"source": "a", "level": "INFO", "message": "x" * 5000}] * 210
        self.assertEqual(self.post(big).status_code, 413)
        ndjson_many = "\n".join(['{"source":"a","level":"INFO","message":"m"}'] * 1001)
        self.assertEqual(self.post(ndjson_many, ctype="application/x-ndjson").status_code, 413)
        self.assertEqual(LogEntry.objects.count(), 0)
        ok_many = [{"source": "a", "level": "INFO", "message": "m"}] * 1000
        self.assertEqual(self.post(ok_many).json()["accepted"], 1000)

    def test_error_lines_emit_one_event_per_pattern(self):
        batch = [{"source": "db", "level": "ERROR", "message": "Slow query 2.3s on 10.0.0.5"},
                 {"source": "db", "level": "ERROR", "message": "Slow query 4.1s on 10.0.0.9"},
                 {"source": "db", "level": "CRITICAL", "message": "Replication stopped"},
                 {"source": "db", "level": "WARN", "message": "not an event"}]
        d = self.post(batch).json()
        self.assertEqual((d["events"], d["events_suppressed"]), (2, 1))
        crit = Event.objects.get(severity="critical")
        self.assertEqual((crit.source, crit.kind), ("observe", "log"))
        self.assertTrue(crit.fingerprint.startswith("observe:log:"))
        self.assertEqual(crit.object_type, "observe.logentry")
        # same patterns again within 10 minutes: no new events
        d = self.post(batch[:3]).json()
        self.assertEqual((d["events"], d["events_suppressed"]), (0, 3))
        # after the window the pattern is new again
        Event.objects.update(occurred_at=timezone.now() - timedelta(minutes=11))
        self.assertEqual(self.post(batch[:1]).json()["events"], 1)
        self.assertEqual(Event.objects.filter(source="observe").count(), 3)

    def test_event_storm_is_capped(self):
        batch = [{"source": f"svc-{i}", "level": "ERROR", "message": "failed"} for i in range(60)]
        d = self.post(batch).json()
        self.assertEqual(d["accepted"], 60)
        self.assertEqual(d["events"], services.MAX_EVENTS_PER_BATCH)
        self.assertEqual(Event.objects.filter(source="observe").count(), services.MAX_EVENTS_PER_BATCH)

    def test_message_pattern(self):
        a = services.message_pattern("Login failed for 'bob' from 10.1.1.5:4433 after 3 tries")
        b = services.message_pattern("Login failed for 'eve' from 10.9.9.9:22 after 12 tries")
        self.assertEqual(a, b)
        self.assertNotEqual(services.log_fingerprint("a", "x"), services.log_fingerprint("b", "x"))


@override_settings(LINKEDEYE_TENANT=T)
class RetentionTests(TestCase):
    @override_settings(LOG_RETENTION_DAYS=7)
    def test_prune(self):
        now = timezone.now()
        log(message="old", ts=now - timedelta(days=8))
        log(message="new", ts=now - timedelta(days=6))
        self.assertEqual(jobs.log_retention(), "pruned 1 log entry")
        self.assertEqual(list(LogEntry.objects.values_list("message", flat=True)), ["new"])

    def test_default_14_days_and_batches(self):
        now = timezone.now()
        for i in range(7):
            log(message=f"old{i}", ts=now - timedelta(days=15))
        log(message="keep", ts=now - timedelta(days=13))
        self.assertEqual(services.prune_logs(batch=3), 7)
        self.assertEqual(LogEntry.objects.count(), 1)


# ------------------------------------------------------------------------------------------- views
@override_settings(LINKEDEYE_TENANT=T, LOG_INGEST_TOKEN="")
class PageTests(TestCase):
    def setUp(self):
        self.viewer, self.operator, self.admin = users()
        self.e1 = exp("node-01", metrics_url="http://10.0.0.1/metrics", site="Mumbai DC", status="active",
                      last_seen=timezone.now(), samples=99)
        self.e2 = exp("snmp-01", category="Network", site="Pune DR")
        log("node-01", "ERROR", "disk failed", site="Mumbai DC")
        log("node-01", "INFO", "cpu 40%", site="Mumbai DC")
        log("other", "WARN", "old line", ts=timezone.now() - timedelta(days=3))
        emit(source="urlchecker", title="Site down", severity="critical", site="Mumbai DC")

    def test_pages_render_for_all_roles(self):
        names = [("observe:exporters", []), ("observe:logs", []), ("observe:events", []), ("observe:docs", []),
                 ("observe:exporter_detail", [self.e1.pk])]
        for user in (self.viewer, self.operator, self.admin):
            c = client_for(user)
            for name, args in names:
                r = c.get(reverse(name, args=args))
                self.assertEqual(r.status_code, 200, f"{name} for {user}")

    def test_url_names(self):
        self.assertEqual(reverse("observe:exporters"), "/monitoring/exporters/")
        self.assertEqual(reverse("observe:logs"), "/logs/")
        self.assertEqual(reverse("observe:events"), "/logs/events/")
        self.assertEqual(reverse("observe:log_ingest"), "/api/v1/logs/")

    def test_login_required(self):
        r = Client().get(reverse("observe:exporters"))
        self.assertEqual(r.status_code, 302)

    def test_exporters_page_real_data(self):
        r = client_for(self.viewer).get(reverse("observe:exporters"))
        self.assertEqual(r.context["total"], 2)
        self.assertEqual(r.context["health"]["active"], 1)
        self.assertEqual(r.context["health"]["not_configured"], 1)
        self.assertEqual(r.context["logs24"], 2)
        self.assertEqual(r.context["events24"], Event.objects.count())   # other modules' listeners may add events
        self.assertEqual(r.context["trend"]["total"], 2)
        self.assertEqual(r.context["top"][0], {"source": "node-01", "n": 2})
        rows = {e.name: e.logs24 for e in r.context["page"]}
        self.assertEqual(rows, {"node-01": 2, "snmp-01": 0})
        self.assertContains(r, "LINKEDEYE_LOG_INGEST_TOKEN")      # not-connected hint
        self.assertNotContains(r, "Add Exporter")                  # viewer has no create button
        self.assertNotContains(r, reverse("observe:exporter_delete", args=[self.e1.pk]))
        r = client_for(self.admin).get(reverse("observe:exporters"), {"category": "Network"})
        self.assertEqual([e.name for e in r.context["page"]], ["snmp-01"])
        self.assertContains(r, reverse("observe:exporter_delete", args=[self.e2.pk]))
        r = client_for(self.admin).get(reverse("observe:exporters"), {"status": "active", "q": "node"})
        self.assertEqual(r.context["page"].paginator.count, 1)

    def test_site_scoping(self):
        site = Site.objects.create(name="Pune DR", code="pune")
        Membership.objects.create(user=self.viewer, site=site, role="viewer")
        c = client_for(self.viewer)
        r = c.get(reverse("observe:exporters"))
        self.assertEqual([e.name for e in r.context["page"]], ["snmp-01"])
        self.assertEqual(c.get(reverse("observe:exporter_detail", args=[self.e1.pk])).status_code, 404)
        r = c.get(reverse("observe:logs"))
        self.assertEqual(r.context["page"].paginator.count, 0)

    def test_site_operator_cannot_edit_other_site(self):
        site = Site.objects.create(name="Pune DR", code="pune")
        Site.objects.create(name="Mumbai DC", code="mum")
        u = User.objects.create_user("siteop")
        Membership.objects.create(user=u, site=site, role="operator")
        c = client_for(u)
        self.assertEqual(c.get(reverse("observe:exporter_edit", args=[self.e2.pk])).status_code, 200)
        r = c.post(reverse("observe:exporter_create"), {"name": "x", "exporter_type": "SNMP", "category": "Network",
                                                         "site": "Mumbai DC", "enabled": "on"})
        self.assertEqual(r.status_code, 200)
        self.assertFalse(Exporter.objects.filter(name="x").exists())

    def test_logs_filters_and_feed(self):
        c = client_for(self.viewer)
        r = c.get(reverse("observe:logs"), {"level": "ERROR"})
        self.assertEqual([e.message for e in r.context["page"]], ["disk failed"])
        self.assertEqual(r.context["level_counts"]["INFO"], 1)      # level KPIs ignore the level filter
        r = c.get(reverse("observe:logs"), {"range": "7d"})
        self.assertEqual(r.context["page"].paginator.count, 3)
        r = c.get(reverse("observe:logs"), {"q": "cpu", "source": "node-01", "site": "Mumbai DC"})
        self.assertEqual(r.context["page"].paginator.count, 1)
        r = c.get(reverse("observe:logs"), {"level": "WARN+", "range": "all"})
        self.assertEqual(r.context["page"].paginator.count, 2)
        r = c.get(reverse("observe:logs"), {"range": "custom", "since": (timezone.localtime() - timedelta(days=4)).strftime("%Y-%m-%dT%H:%M"),
                                            "until": (timezone.localtime() - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M")})
        self.assertEqual([e.message for e in r.context["page"]], ["old line"])
        d = c.get(reverse("observe:logs_feed"), {"source": "node-01"}).json()
        self.assertEqual(len(d["rows"]), 2)
        self.assertEqual(d["rows"][0]["source"], "node-01")
        last = d["last_id"]
        self.assertEqual(c.get(reverse("observe:logs_feed"), {"after": last}).json()["rows"], [])
        log("node-01", "INFO", "brand new", site="Mumbai DC")
        d = c.get(reverse("observe:logs_feed"), {"after": last}).json()
        self.assertEqual([x["message"] for x in d["rows"]], ["brand new"])

    def test_csv_exports(self):
        c = client_for(self.viewer)
        body = b"".join(c.get(reverse("observe:logs_export"), {"level": "ERROR"}).streaming_content).decode()
        self.assertIn("disk failed", body)
        self.assertNotIn("cpu 40%", body)
        body = b"".join(c.get(reverse("observe:exporters_export")).streaming_content).decode()
        self.assertTrue(body.startswith("name,type,category"))
        self.assertIn("snmp-01", body)
        body = b"".join(c.get(reverse("observe:events_export")).streaming_content).decode()
        self.assertIn("Site down", body)

    def test_csv_formula_injection_neutralised(self):
        log("evil", "INFO", "=HYPERLINK(\"http://x\")")
        body = b"".join(client_for(self.viewer).get(reverse("observe:logs_export")).streaming_content).decode()
        self.assertIn("'=HYPERLINK", body)

    def test_events_page_filters(self):
        emit(source="observe", title="Exporter x failing", severity="warning", fingerprint="exporter:9")
        c = client_for(self.viewer)
        r = c.get(reverse("observe:events"), {"severity": "critical"})
        self.assertEqual([e.title for e in r.context["page"]], ["Site down"])
        r = c.get(reverse("observe:events"), {"source": "observe"})
        self.assertEqual(r.context["page"].paginator.count, 1)
        r = c.get(reverse("observe:events"), {"fingerprint": "exporter:9"})
        self.assertEqual(r.context["page"].paginator.count, 1)
        self.assertEqual(r.context["sev_counts"]["critical"], 1)
        r = c.get(reverse("observe:logs"), {"eseverity": "warning", "esource": "observe"})
        self.assertEqual([e.title for e in r.context["events"]], ["Exporter x failing"])
        r = c.get(reverse("observe:logs"), {"eseverity": "critical"})
        self.assertEqual({e.severity for e in r.context["events"]}, {"critical"})


@override_settings(LINKEDEYE_TENANT=T, PROBE_WORKERS=1)
class MutationTests(TestCase):
    def setUp(self):
        self.viewer, self.operator, self.admin = users()

    def form(self, **kw):
        data = {"name": "node-02", "exporter_type": "Node Exporter", "category": "Servers", "target": "srv-02",
                "metrics_url": "http://10.0.0.2:9100/metrics", "site": "", "enabled": "on", "description": ""}
        data.update(kw)
        return data

    def test_viewer_cannot_mutate(self):
        e = exp(metrics_url="http://10.0.0.1/metrics")
        c = client_for(self.viewer)
        self.assertEqual(c.get(reverse("observe:exporter_create")).status_code, 403)
        self.assertEqual(c.get(reverse("observe:exporters_import")).status_code, 403)
        for name in ("observe:exporter_check", "observe:exporter_delete"):
            r = c.post(reverse(name, args=[e.pk]))
            self.assertEqual(r.status_code, 302)
        r = c.post(reverse("observe:exporter_check", args=[e.pk]), HTTP_X_CSRFTOKEN="x", HTTP_ACCEPT="application/json")
        self.assertEqual(r.status_code, 403)
        self.assertTrue(Exporter.objects.filter(pk=e.pk).exists())
        self.assertEqual(AuditEvent.objects.count(), 0)

    def test_create_requires_csrf(self):
        c = client_for(self.operator, csrf=True)
        r = c.post(reverse("observe:exporter_create"), self.form())
        self.assertEqual(r.status_code, 403)
        self.assertFalse(Exporter.objects.exists())

    def test_create_scrapes_and_audits(self):
        c = client_for(self.operator)
        with mock.patch.object(scrape, "scrape", return_value=ok(7)) as m:
            r = c.post(reverse("observe:exporter_create"), self.form())
        e = Exporter.objects.get(name="node-02")
        self.assertRedirects(r, e.get_absolute_url())
        m.assert_called_once()
        self.assertEqual((e.status, e.samples, e.tenant_key), ("active", 7, T))
        a = AuditEvent.objects.get(action="create")
        self.assertEqual((a.object_type, a.object_id, a.actor_name), ("observe.exporter", str(e.pk), "operator"))

    def test_create_without_url_is_not_configured(self):
        c = client_for(self.operator)
        with mock.patch.object(scrape, "scrape") as m:
            r = c.post(reverse("observe:exporter_create"), self.form(metrics_url=""), follow=True)
        m.assert_not_called()
        self.assertEqual(Exporter.objects.get().status, "not_configured")
        self.assertContains(r, "Not Configured")

    def test_validation(self):
        exp("node-02")
        c = client_for(self.operator)
        r = c.post(reverse("observe:exporter_create"), self.form(name="NODE-02"))
        self.assertContains(r, "already exists")
        r = c.post(reverse("observe:exporter_create"), self.form(name="n3", metrics_url="ftp://x/metrics"))
        self.assertEqual(r.status_code, 200)
        r = c.post(reverse("observe:exporter_create"), self.form(name="n4", metrics_url="http://u:p@example.com/metrics"))
        self.assertContains(r, "Credentials")
        self.assertEqual(Exporter.objects.count(), 1)

    def test_edit_audits_changes_and_disable(self):
        e = exp("node-02", metrics_url="http://10.0.0.2:9100/metrics", status="active")
        c = client_for(self.operator)
        with mock.patch.object(scrape, "scrape") as m:
            r = c.post(reverse("observe:exporter_edit", args=[e.pk]), self.form(enabled="", target="srv-x"))
        self.assertEqual(r.status_code, 302)
        m.assert_not_called()
        e.refresh_from_db()
        self.assertEqual((e.status, e.target), ("inactive", "srv-x"))
        a = AuditEvent.objects.get(action="update")
        self.assertEqual(sorted(a.details["changed"]), ["enabled", "target"])

    def test_delete_admin_only(self):
        e = exp()
        r = client_for(self.operator).post(reverse("observe:exporter_delete", args=[e.pk]))
        self.assertEqual(r.status_code, 302)
        self.assertTrue(Exporter.objects.filter(pk=e.pk).exists())
        r = client_for(self.admin).post(reverse("observe:exporter_delete", args=[e.pk]))
        self.assertRedirects(r, reverse("observe:exporters"))
        self.assertFalse(Exporter.objects.filter(pk=e.pk).exists())
        a = AuditEvent.objects.get(action="delete")
        self.assertEqual(a.details["name"], "node-01")
        self.assertEqual(client_for(self.admin).get(reverse("observe:exporter_delete", args=[e.pk])).status_code, 405)

    def test_run_check(self):
        e = exp(metrics_url="http://10.0.0.1/metrics")
        c = client_for(self.operator)
        with mock.patch.object(scrape, "scrape", return_value=fail("HTTP 500")):
            r = c.post(reverse("observe:exporter_check", args=[e.pk]), HTTP_ACCEPT="application/json")
        self.assertEqual(r.json()["status"], "error")
        self.assertEqual(AuditEvent.objects.get(action="run").details["result_status"], "error")
        with mock.patch.object(scrape, "scrape", return_value=ok()):
            r = c.post(reverse("observe:exporter_check", args=[e.pk]))
        self.assertRedirects(r, e.get_absolute_url())
        e.refresh_from_db()
        self.assertEqual(e.status, "active")
        self.assertEqual(Event.objects.filter(fingerprint=f"exporter:{e.pk}", source="observe").count(), 2)

    def test_run_check_without_url_is_skipped(self):
        e = exp()
        with mock.patch.object(scrape, "scrape") as m:
            r = client_for(self.operator).post(reverse("observe:exporter_check", args=[e.pk]), HTTP_ACCEPT="application/json")
        self.assertEqual(r.status_code, 409)
        m.assert_not_called()

    def test_check_all(self):
        exp("a", metrics_url="http://10.0.0.1/metrics")
        exp("b", metrics_url="http://10.0.0.2/metrics", enabled=False)
        exp("c")
        with mock.patch.object(scrape, "scrape", return_value=ok()) as m:
            r = client_for(self.operator).post(reverse("observe:exporter_check_all"), HTTP_ACCEPT="application/json")
        self.assertEqual(r.json()["checked"], 1)
        self.assertEqual(m.call_count, 1)
        self.assertTrue(AuditEvent.objects.filter(action="run", object_type="observe.exporter").exists())

    def test_import(self):
        exp("existing", target="old")
        csv_text = ("name,type,category,target,metrics_url,site,enabled,description\n"
                    "imp-1,SNMP,network,10.0.0.1,,Mumbai DC,yes,\n"
                    "imp-2,Node Exporter,Servers,srv,http://10.0.0.9:9100/metrics,,no,\n"
                    "bad,X,Nope,,,,,\n"
                    "existing,Node Exporter,Servers,new,,,yes,\n")
        c = client_for(self.operator)
        f = SimpleUploadedFile("e.csv", csv_text.encode(), content_type="text/csv")
        r = c.post(reverse("observe:exporters_import"), {"file": f})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.context["report"]["created"], 2)
        self.assertEqual(len(r.context["report"]["errors"]), 2)
        self.assertEqual(Exporter.objects.get(name="imp-1").category, "Network")
        self.assertEqual(Exporter.objects.get(name="imp-2").status, "inactive")
        self.assertEqual(Exporter.objects.get(name="existing").target, "old")
        f = SimpleUploadedFile("e.csv", csv_text.encode(), content_type="text/csv")
        r = c.post(reverse("observe:exporters_import"), {"file": f, "update_existing": "on"})
        self.assertEqual(Exporter.objects.get(name="existing").target, "new")
        self.assertTrue(AuditEvent.objects.filter(action="import").exists())
        r = c.post(reverse("observe:exporters_import"), {"file": SimpleUploadedFile("x.csv", b"foo,bar\n1,2\n")})
        self.assertContains(r, "header row must contain")


@override_settings(LINKEDEYE_TENANT=T)
class SeedTests(TestCase):
    def test_seed_is_idempotent_and_marked(self):
        call_command("seed_observe", "--lines", "50", stdout=StringIO())
        call_command("seed_observe", "--lines", "50", stdout=StringIO())
        self.assertEqual(Exporter.objects.count(), 13)
        self.assertTrue(all(e.status == "not_configured" and not e.metrics_url and "Example" in e.description
                            for e in Exporter.objects.all()))
        self.assertEqual(LogEntry.objects.count(), 50)
        self.assertTrue(all(e.attributes.get("example") and e.message.startswith("[example]") for e in LogEntry.objects.all()))
        self.assertEqual(Event.objects.count(), 0)
        call_command("seed_observe", "--refresh-logs", "--lines", "20", stdout=StringIO())
        self.assertEqual(LogEntry.objects.count(), 20)
