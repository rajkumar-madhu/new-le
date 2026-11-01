"""Telemetry tests. Every Prometheus and Nagios call is mocked; nothing touches the network."""
import base64
import io
import json
import urllib.error
from datetime import timedelta
from unittest import mock

from django.apps import apps
from django.contrib.auth.models import User
from django.core.cache import cache
from django.core.management import call_command
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from core import jobs as core_jobs
from core import prometheus
from core.models import AuditEvent, Event, Membership, Site

from . import alerts as alert_svc
from . import explorer, fmt, hosts, nagios, targets
from .models import Alert, SavedQuery


def _has_model(app_label, model):
    """True when the other module is present with the model (main may carry an empty stub app)."""
    try:
        apps.get_model(app_label, model)
        return True
    except LookupError:
        return False

PROM = "http://prom.test:9090"
TOKEN = "s3cret-token-value"

# ----------------------------------------------------------------------------- fake Prometheus
HOSTS = {  # instance: (up, cpu, mem, disk, load1, cores)
    "web-01:9100": (1, 20.0, 40.0, 30.0, 0.5, 4),
    "db-01:9100": (1, 50.0, 95.0, 60.0, 2.0, 8),
    "app-01:9100": (1, 80.0, 50.0, 40.0, 1.0, 4),
    "old-01:9100": (0, None, None, None, None, None),
}


def _row(inst, v, **labels):
    return {"metric": {"instance": inst, **labels}, "value": v}


def fake_query(q, at=None):
    def each(i):
        return [_row(inst, vals[i]) for inst, vals in HOSTS.items() if vals[i] is not None]
    if q.startswith("up{"):
        return [_row(inst, float(vals[0]), job="node", __name__="up") for inst, vals in HOSTS.items()]
    if "count by (instance)" in q:
        return each(5)
    if 'mode="idle"' in q:
        return each(1)
    if "MemAvailable" in q:
        return each(2)
    if "node_filesystem_avail_bytes" in q:
        return each(3)
    if "node_load1" in q:
        return each(4)
    if "receive_bytes" in q:
        return [_row(i, 1024.0 * 1024) for i in HOSTS if HOSTS[i][0]]
    if "transmit_bytes" in q:
        return [_row(i, 2048.0) for i in HOSTS if HOSTS[i][0]]
    if "node_time_seconds" in q:
        return [_row(i, 90000.0) for i in HOSTS if HOSTS[i][0]]
    if "prometheus_tsdb_head_series" in q:
        return [{"metric": {}, "value": 1234.0}]
    return []


def fake_range(q, seconds=3600, step=None):
    now = 1_700_000_000.0
    return [{"metric": {"instance": inst}, "values": [(now + k * 60, 10.0 + k) for k in range(5)]}
            for inst, vals in HOSTS.items() if vals[0]]


def prom_patches():
    return [mock.patch("core.prometheus.query", side_effect=fake_query),
            mock.patch("core.prometheus.query_range", side_effect=fake_range)]


class PromMixin:
    def start_prom(self):
        ps = prom_patches()
        mocks = [p.start() for p in ps]
        for p in ps:
            self.addCleanup(p.stop)
        return mocks


def users():
    viewer = User.objects.create_user("viewer", password="pw")
    operator = User.objects.create_user("operator", password="pw", is_staff=True)
    admin = User.objects.create_superuser("root", "root@example.com", "pw")
    return viewer, operator, admin


def am_payload(*alerts, status="firing", version="4"):
    return {"version": version, "groupKey": "{}:{alertname=\"X\"}", "status": status, "receiver": "linkedeye",
            "groupLabels": {}, "commonLabels": {}, "commonAnnotations": {}, "externalURL": "http://am:9093",
            "alerts": list(alerts)}


def am_alert(fp="abc123", status="firing", severity="critical", name="HostDown", instance="db-01:9100", **labels):
    return {"status": status, "fingerprint": fp,
            "labels": {"alertname": name, "severity": severity, "instance": instance, "job": "node", **labels},
            "annotations": {"summary": f"{name} summary", "description": "details"},
            "startsAt": "2026-10-31T10:00:00.123456789Z",
            "endsAt": "2026-10-31T11:00:00Z" if status == "resolved" else "0001-01-01T00:00:00Z",
            "generatorURL": "http://prometheus:9090/graph?g0.expr=up"}


# ============================================================================= helpers / models
class FmtTests(TestCase):
    def test_parse_ts(self):
        dt = fmt.parse_ts("2026-10-31T10:00:00.123456789Z")
        self.assertEqual((dt.year, dt.hour, dt.microsecond), (2026, 10, 123456))
        self.assertIsNone(fmt.parse_ts("0001-01-01T00:00:00Z"))
        self.assertIsNone(fmt.parse_ts("garbage"))
        self.assertIsNone(fmt.parse_ts(None))

    def test_human_formats(self):
        self.assertEqual(fmt.human_bytes(1536), "1.5 KB")
        self.assertEqual(fmt.human_rate(None), "–")
        self.assertEqual(fmt.human_duration(90061), "1d 1h")
        self.assertEqual(fmt.human_number(12345678.0), "12.3M")
        self.assertEqual(fmt.human_number(""), "–")
        self.assertEqual(fmt.human_number(float("nan")), "NaN")

    def test_promql_quoting_and_series_names(self):
        self.assertEqual(fmt.promql_string('a"b\\c'), '"a\\"b\\\\c"')
        self.assertEqual(fmt.series_name({"__name__": "up", "job": "node"}), 'up{job="node"}')
        self.assertEqual(fmt.series_name({}), "{}")


class ModelTests(TestCase):
    def test_alert_helpers(self):
        a = Alert.objects.create(fingerprint="f1", alertname="X", severity="critical",
                                 labels={"alertname": "X", "severity": "critical", "team": "db", "instance": "h"},
                                 starts_at=timezone.now() - timedelta(minutes=5))
        self.assertEqual(a.severity_tone, "crit")
        self.assertEqual(a.extra_labels, [("team", "db")])
        self.assertEqual(a.event_fingerprint, "am:f1")
        self.assertGreaterEqual(a.duration_seconds, 299)
        self.assertFalse(a.acknowledged)
        self.assertEqual(str(a), "X")

    def test_fingerprint_unique(self):
        from django.db import IntegrityError
        Alert.objects.create(fingerprint="dup", alertname="A")
        with self.assertRaises(IntegrityError):
            Alert.objects.create(fingerprint="dup", alertname="B")

    def test_saved_query_unique_per_owner(self):
        from django.db import IntegrityError
        u = User.objects.create_user("u")
        SavedQuery.objects.create(name="cpu", promql="up", owner=u)
        with self.assertRaises(IntegrityError):
            SavedQuery.objects.create(name="cpu", promql="up", owner=u)


# ============================================================================= explorer policy
class ExplorerPolicyTests(TestCase):
    def test_length_limit(self):
        with self.assertRaises(explorer.PolicyError):
            explorer.check("x" * 2001, 3600)
        self.assertEqual(explorer.check("x" * 2000, 3600)[0], "x" * 2000)

    def test_range_limit(self):
        with self.assertRaises(explorer.PolicyError):
            explorer.check("up", 7 * 86400 + 1)
        explorer.check("up", 7 * 86400)

    def test_step_bounded_to_1100_points(self):
        for seconds in (300, 3600, 86400, 7 * 86400):
            _q, s, step, _n = explorer.check("up", seconds, 1)
            self.assertLessEqual(s // step + 1, explorer.MAX_POINTS)
        _q, _s, step, notes = explorer.check("up", 7 * 86400, 15)
        self.assertEqual(step, 551)
        self.assertTrue(notes)
        self.assertEqual(explorer.check("up", 3600, 60)[2], 60)

    def test_rejects_empty_and_control_chars(self):
        for bad in ("", "   ", "up\x00"):
            with self.assertRaises(explorer.PolicyError):
                explorer.check(bad, 3600)

    def test_parse_duration(self):
        self.assertEqual(explorer.parse_duration("5m"), 300)
        self.assertEqual(explorer.parse_duration("30"), 30)
        self.assertIsNone(explorer.parse_duration("5 minutes"))

    def test_run_caps_series_at_40(self):
        rows = [{"metric": {"__name__": "m", "i": str(i)}, "values": [(1.0, float(i)), (2.0, float(i) + 1)]} for i in range(55)]
        with mock.patch("core.prometheus.query_range", return_value=rows) as qr:
            res = explorer.run("m", 3600, 60)
        qr.assert_called_once_with("m", 3600, 60)
        self.assertEqual(res["total"], 55)
        self.assertEqual(len(res["series"]), 40)
        self.assertEqual(res["series"][0]["last"], 55.0)  # highest last value first
        self.assertEqual(len(res["chart"]["series"]), 40)
        self.assertTrue(res["notes"])


# ============================================================================= hosts / targets services
@override_settings(PROMETHEUS_URL=PROM)
class HostServiceTests(PromMixin, TestCase):
    def setUp(self):
        cache.clear()

    def test_fetch_hosts_health(self):
        self.start_prom()
        hs = {h["instance"]: h for h in hosts.fetch_hosts()}
        self.assertEqual(hs["old-01:9100"]["health"], "down")
        self.assertEqual(hs["db-01:9100"]["health"], "critical")   # memory 95%
        self.assertEqual(hs["app-01:9100"]["health"], "warning")   # cpu 80%
        self.assertEqual(hs["web-01:9100"]["health"], "healthy")
        self.assertAlmostEqual(hs["db-01:9100"]["load_per_core"], 0.25)
        s = hosts.summarize(list(hs.values()))
        self.assertEqual((s["total"], s["up"], s["down"], s["critical"]), (4, 3, 1, 1))
        self.assertEqual(list(hosts.fetch_hosts())[0]["health"], "down")  # sorted worst first

    def test_hosts_are_cached(self):
        q, _r = self.start_prom()
        hosts.fetch_hosts()
        n = q.call_count
        hosts.fetch_hosts()
        self.assertEqual(q.call_count, n)
        hosts.fetch_hosts(use_cache=False)
        self.assertGreater(q.call_count, n)

    def test_instance_is_escaped_in_detail_queries(self):
        qs = hosts.detail_queries('evil"} or vector(1) #')
        self.assertIn('instance="evil\\"} or vector(1) #"', qs["cpu"])

    def test_cmdb_join(self):
        if not _has_model("cmdb", "ConfigurationItem"):
            self.skipTest("cmdb not installed")
        CI = apps.get_model("cmdb", "ConfigurationItem")
        try:
            CI.objects.create(name="DB Server 1", ci_type="server", prometheus_instance="db-01:9100", site="DR Site")
        except Exception as e:  # pragma: no cover - other module's required fields
            self.skipTest(f"cannot create CI: {e}")
        m = hosts.cmdb_map(["db-01:9100", "web-01:9100"])
        self.assertEqual(m["db-01:9100"].name, "DB Server 1")
        self.assertNotIn("web-01:9100", m)


class TargetsServiceTests(TestCase):
    def test_normalize_and_summaries(self):
        raw = [
            {"labels": {"job": "node", "instance": "a:9100", "env": "prod"}, "scrapePool": "node", "scrapeUrl": "http://a:9100/metrics",
             "health": "up", "lastError": "", "lastScrape": "2026-10-31T10:00:00.5Z", "lastScrapeDuration": 0.02},
            {"labels": {"job": "node", "instance": "b:9100"}, "scrapePool": "node", "scrapeUrl": "http://b:9100/metrics",
             "health": "down", "lastError": "connection refused", "lastScrape": "2026-10-31T10:00:00Z", "lastScrapeDuration": 0.04},
            {"labels": {"job": "bb", "instance": "https://x"}, "health": "unknown", "lastScrape": "0001-01-01T00:00:00Z"},
        ]
        rows = [targets.normalize(t) for t in raw]
        self.assertEqual(rows[0]["labels"], [("env", "prod")])
        self.assertIsNone(rows[2]["last_scrape"])
        k = targets.kpis(rows)
        self.assertEqual((k["total"], k["up"], k["down"], k["unknown"], k["jobs"]), (3, 1, 1, 1, 2))
        self.assertAlmostEqual(k["avg_duration"], 0.03)
        jobs = {j["job"]: j for j in targets.jobs_summary(rows)}
        self.assertEqual(jobs["node"]["health"], "down")
        self.assertEqual(jobs["bb"]["health"], "unknown")


# ============================================================================= Nagios
class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def nagios_body(query):
    if query == "hostlist":
        data = {"hostlist": {"web": {"name": "web", "status": 2, "plugin_output": "PING OK", "last_check": 1_700_000_000_000},
                             "db": {"name": "db", "status": 4, "plugin_output": "CRITICAL - down", "problem_has_been_acknowledged": True},
                             "dr": {"name": "dr", "status": "unreachable"}}}
    else:
        data = {"servicelist": {"web": {"HTTP": {"status": 2, "plugin_output": "OK"}, "Disk": {"status": 4, "plugin_output": "WARN"}},
                                "db": {"MySQL": {"status": 16, "plugin_output": "CRIT"}, "Backup": {"status": "unknown"}}}}
    return json.dumps({"format_version": 0, "result": {"query_time": 1_700_000_000_000, "type_code": 0, "type_text": "Success",
                                                       "program_version": "4.4.14"}, "data": data}).encode()


def fake_urlopen(req, timeout=None):
    from urllib.parse import parse_qs, urlparse
    q = parse_qs(urlparse(req.full_url).query)["query"][0]
    return FakeResp(nagios_body(q))


@override_settings(NAGIOS_URL="https://nagios.test/nagios", NAGIOS_USER="nagiosadmin", NAGIOS_PASSWORD="pw")
class NagiosTests(TestCase):
    def setUp(self):
        cache.clear()

    def test_fetch_and_summarize(self):
        with mock.patch("telemetry.nagios._urlopen", side_effect=fake_urlopen) as uo:
            st = nagios.fetch_status()
        self.assertEqual(uo.call_count, 2)
        req = uo.call_args_list[0][0][0]
        self.assertTrue(req.full_url.startswith("https://nagios.test/nagios/cgi-bin/statusjson.cgi?query=hostlist"))
        self.assertIn("details=true", req.full_url)
        self.assertEqual(req.get_header("Authorization"), "Basic " + base64.b64encode(b"nagiosadmin:pw").decode())
        self.assertEqual(st["hosts"][0]["state"], "down")  # worst first
        self.assertEqual({h["name"]: h["state"] for h in st["hosts"]}, {"web": "up", "db": "down", "dr": "unreachable"})
        self.assertEqual(st["services"][0]["state"], "critical")
        s = nagios.summarize(st)
        self.assertEqual(s["host_counts"]["down"], 1)
        self.assertEqual(s["service_counts"], {"critical": 1, "warning": 1, "unknown": 1, "pending": 0, "ok": 1})
        self.assertEqual(s["unhandled"], 1 + 3)  # db is acknowledged

    def test_cached_for_30_seconds(self):
        with mock.patch("telemetry.nagios._urlopen", side_effect=fake_urlopen) as uo:
            nagios.fetch_status()
            nagios.fetch_status()
        self.assertEqual(uo.call_count, 2)

    def test_errors(self):
        err = urllib.error.HTTPError("https://nagios.test", 401, "Unauthorized", {}, None)
        with mock.patch("telemetry.nagios._urlopen", side_effect=err):
            with self.assertRaisesRegex(nagios.NagiosError, "credentials"):
                nagios.fetch_status()
        cache.clear()
        with mock.patch("telemetry.nagios._urlopen", side_effect=urllib.error.URLError("timed out")):
            with self.assertRaisesRegex(nagios.NagiosError, "unreachable"):
                nagios.fetch_status()
        cache.clear()
        with mock.patch("telemetry.nagios._urlopen", return_value=FakeResp(b"<html>login</html>")):
            with self.assertRaisesRegex(nagios.NagiosError, "JSON"):
                nagios.fetch_status()

    def test_url_variants(self):
        for base, expected in (("https://n/nagios", "https://n/nagios/cgi-bin/statusjson.cgi"),
                               ("https://n/nagios/cgi-bin/", "https://n/nagios/cgi-bin/statusjson.cgi"),
                               ("https://n/x/statusjson.cgi", "https://n/x/statusjson.cgi")):
            with override_settings(NAGIOS_URL=base):
                self.assertEqual(nagios.statusjson_url(), expected)

    @override_settings(NAGIOS_URL="")
    def test_not_configured(self):
        with mock.patch.dict("os.environ", {"LINKEDEYE_NAGIOS_URL": ""}):
            self.assertFalse(nagios.configured())
            with self.assertRaises(nagios.NagiosError):
                nagios.fetch_status()


# ============================================================================= webhook
@override_settings(ALERTMANAGER_WEBHOOK_TOKEN=TOKEN, INCIDENT_AUTO_CREATE=False)
class WebhookTests(TestCase):
    url = "/api/v1/alertmanager/"

    def setUp(self):
        self.c = Client(enforce_csrf_checks=True)

    def post(self, payload, token=TOKEN, raw=None, **extra):
        headers = {"HTTP_AUTHORIZATION": f"Bearer {token}"} if token is not None else {}
        body = raw if raw is not None else json.dumps(payload)
        return self.c.post(self.url, data=body, content_type="application/json", **headers, **extra)

    def test_url_name(self):
        self.assertEqual(reverse("telemetry:alertmanager_webhook"), self.url)

    @override_settings(ALERTMANAGER_WEBHOOK_TOKEN="")
    def test_disabled_without_token(self):
        r = self.post(am_payload(am_alert()), token="")
        self.assertEqual(r.status_code, 503)
        self.assertIn("LINKEDEYE_ALERTMANAGER_WEBHOOK_TOKEN", r.json()["error"])
        self.assertEqual(Alert.objects.count(), 0)

    def test_rejects_bad_tokens(self):
        with self.assertLogs("linkedeye.telemetry", "WARNING"):
            for tok in (None, "wrong", TOKEN + "x", "", "ünïcode"):
                r = self.post(am_payload(am_alert()), token=tok)
                self.assertEqual(r.status_code, 401, tok)
            r = self.c.post(self.url, data="{}", content_type="application/json", HTTP_AUTHORIZATION=f"Basic {TOKEN}")
        self.assertEqual(r.status_code, 401)
        self.assertEqual(Alert.objects.count(), 0)

    def test_uses_constant_time_compare(self):
        with mock.patch("telemetry.views.webhook.hmac.compare_digest", return_value=False) as cd, \
                self.assertLogs("linkedeye.telemetry", "WARNING"):
            self.assertEqual(self.post(am_payload(am_alert())).status_code, 401)
        cd.assert_called_once()

    def test_method_and_size_and_format(self):
        self.assertEqual(self.c.get(self.url).status_code, 405)
        big = json.dumps(am_payload(am_alert(description="x" * (1024 * 1024))))
        self.assertEqual(self.post(None, raw=big).status_code, 413)
        self.assertEqual(self.post(None, raw="not json").status_code, 400)
        self.assertEqual(self.post(am_payload(am_alert(), version="3")).status_code, 400)
        self.assertEqual(self.post({"version": "4", "alerts": "nope"}).status_code, 400)
        self.assertEqual(self.post(am_payload(am_alert(status="weird"))).status_code, 400)

    def test_firing_creates_alert_event_and_audit(self):
        r = self.post(am_payload(am_alert(team="dba")))
        self.assertEqual(r.status_code, 200, r.content)
        self.assertEqual(r.json()["created"], 1)
        a = Alert.objects.get(fingerprint="abc123")
        self.assertEqual((a.status, a.alertname, a.severity, a.instance, a.job), ("firing", "HostDown", "critical", "db-01:9100", "node"))
        self.assertEqual(a.labels["team"], "dba")
        self.assertEqual(a.summary, "HostDown summary")
        self.assertEqual(a.starts_at.microsecond, 123456)
        self.assertIsNone(a.ends_at)
        ev = Event.objects.get(fingerprint="am:abc123")
        self.assertEqual((ev.severity, ev.source, ev.kind), ("critical", "telemetry", "alert"))
        self.assertEqual(ev.data["host"], "db-01")
        self.assertTrue(AuditEvent.objects.filter(action="ingest", object_type="telemetry.alert").exists())

    def test_state_changes_emit_once(self):
        self.post(am_payload(am_alert()))
        self.post(am_payload(am_alert()))  # repeat notification: no new event
        self.assertEqual(Event.objects.filter(fingerprint="am:abc123").count(), 1)
        a = Alert.objects.get()
        self.assertEqual(a.receive_count, 2)
        a.acknowledged_at = timezone.now()
        a.save()
        self.post(am_payload(am_alert(status="resolved"), status="resolved"))
        a.refresh_from_db()
        self.assertEqual(a.status, "resolved")
        self.assertIsNotNone(a.ends_at)
        self.assertEqual(Event.objects.filter(fingerprint="am:abc123").latest("pk").severity, "ok")
        self.post(am_payload(am_alert()))  # re-fires: new event, acknowledgement cleared
        a.refresh_from_db()
        self.assertEqual((a.status, a.fire_count, a.acknowledged_at), ("firing", 2, None))
        self.assertEqual(Event.objects.filter(fingerprint="am:abc123").count(), 3)
        self.post(am_payload(am_alert(severity="warning")))  # severity change while firing
        self.assertEqual(Event.objects.filter(fingerprint="am:abc123").latest("pk").severity, "warning")

    def test_severity_mapping(self):
        self.assertEqual(alert_svc.event_severity("firing", "page"), "critical")
        self.assertEqual(alert_svc.event_severity("firing", "Critical"), "critical")
        self.assertEqual(alert_svc.event_severity("firing", "warning"), "warning")
        self.assertEqual(alert_svc.event_severity("firing", "info"), "info")
        self.assertEqual(alert_svc.event_severity("resolved", "critical"), "ok")
        self.post(am_payload(am_alert(fp="p1", severity="page")))
        self.assertEqual(Event.objects.get(fingerprint="am:p1").data["priority"], "P1")

    def test_new_resolved_alert_stored_without_event(self):
        self.post(am_payload(am_alert(fp="r1", status="resolved"), status="resolved"))
        self.assertEqual(Alert.objects.get(fingerprint="r1").status, "resolved")
        self.assertFalse(Event.objects.filter(fingerprint="am:r1").exists())

    def test_fingerprint_derived_when_missing(self):
        al = am_alert()
        del al["fingerprint"]
        self.post(am_payload(al))
        self.post(am_payload(al))
        self.assertEqual(Alert.objects.count(), 1)
        self.assertEqual(len(Alert.objects.get().fingerprint), 16)

    @override_settings(INCIDENT_AUTO_CREATE=True)
    def test_critical_alert_opens_service_desk_incident(self):
        if not _has_model("servicedesk", "Ticket"):
            self.skipTest("servicedesk not installed")
        Ticket = apps.get_model("servicedesk", "Ticket")
        self.post(am_payload(am_alert(fp="inc1")))
        self.assertTrue(Ticket.objects.filter(fingerprint="am:inc1", kind="incident").exists())


# ============================================================================= pages + permissions
class PageTests(PromMixin, TestCase):
    pages = ["telemetry:infrastructure", "telemetry:nagios", "telemetry:prometheus", "telemetry:alertmanager", "telemetry:explorer"]

    def setUp(self):
        cache.clear()
        self.viewer, self.operator, self.admin = users()

    def test_url_paths(self):
        self.assertEqual(reverse("telemetry:infrastructure"), "/monitoring/infrastructure/")
        self.assertEqual(reverse("telemetry:nagios"), "/monitoring/nagios/")
        self.assertEqual(reverse("telemetry:prometheus"), "/monitoring/prometheus/")
        self.assertEqual(reverse("telemetry:alertmanager"), "/monitoring/alerts/")
        self.assertEqual(reverse("telemetry:explorer"), "/monitoring/metrics-explorer/")

    def test_login_required(self):
        r = Client().get(reverse("telemetry:infrastructure"))
        self.assertEqual(r.status_code, 302)

    @override_settings(PROMETHEUS_URL="", NAGIOS_URL="", ALERTMANAGER_WEBHOOK_TOKEN="")
    def test_not_connected_states(self):
        self.client.force_login(self.viewer)
        with mock.patch.dict("os.environ", {"LINKEDEYE_NAGIOS_URL": ""}), \
                mock.patch("core.prometheus.query", side_effect=AssertionError("must not query")):
            for name in self.pages:
                r = self.client.get(reverse(name))
                self.assertEqual(r.status_code, 200, name)
                self.assertContains(r, "not connected")
        self.assertContains(self.client.get(reverse("telemetry:infrastructure")), "LINKEDEYE_PROMETHEUS_URL")
        self.assertContains(self.client.get(reverse("telemetry:prometheus")), "LINKEDEYE_PROMETHEUS_URL")
        self.assertContains(self.client.get(reverse("telemetry:nagios")), "NAGIOS_URL")
        self.assertContains(self.client.get(reverse("telemetry:alertmanager")), "LINKEDEYE_ALERTMANAGER_WEBHOOK_TOKEN")

    @override_settings(PROMETHEUS_URL=PROM)
    def test_infrastructure_renders_hosts(self):
        self.start_prom()
        self.client.force_login(self.viewer)
        r = self.client.get(reverse("telemetry:infrastructure"))
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "db-01:9100")
        self.assertContains(r, "Critical")
        self.assertContains(r, 'data-chart="spark"')
        r = self.client.get(reverse("telemetry:infrastructure") + "?health=down")
        self.assertContains(r, "old-01:9100")
        self.assertContains(r, "Hosts (1)")
        r = self.client.get(reverse("telemetry:infrastructure") + "?format=csv")
        self.assertEqual(r["Content-Type"], "text/csv; charset=utf-8")
        self.assertIn("db-01:9100", r.content.decode())

    @override_settings(PROMETHEUS_URL=PROM)
    def test_prometheus_error_is_shown(self):
        self.client.force_login(self.viewer)
        with mock.patch("core.prometheus.query", side_effect=prometheus.PrometheusError("Prometheus unreachable: boom")):
            r = self.client.get(reverse("telemetry:infrastructure"))
        self.assertContains(r, "Prometheus unreachable: boom")
        self.assertNotContains(r, "Traceback")

    @override_settings(PROMETHEUS_URL=PROM)
    def test_host_detail(self):
        self.start_prom()
        self.client.force_login(self.viewer)
        r = self.client.get(reverse("telemetry:host_detail", args=["db-01:9100"]) + "?range=6h")
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Memory Used")
        self.assertContains(r, 'id="c-cpu"')
        with mock.patch("core.prometheus.query", return_value=[]):
            r = self.client.get(reverse("telemetry:host_detail", args=["gone:9100"]))
        self.assertEqual(r.status_code, 404)
        self.assertContains(r, "Host not found", status_code=404)

    @override_settings(PROMETHEUS_URL=PROM)
    def test_prometheus_page(self):
        tgt = [{"labels": {"job": "node", "instance": "a:9100"}, "scrapePool": "node", "scrapeUrl": "http://a:9100/metrics",
                "health": "down", "lastError": "connection refused", "lastScrape": "2026-10-31T10:00:00Z", "lastScrapeDuration": 0.5}]
        self.client.force_login(self.viewer)
        with mock.patch("core.prometheus.targets", return_value=tgt), \
                mock.patch("core.prometheus.query", side_effect=fake_query), \
                mock.patch("core.prometheus.alerts", return_value=[{"state": "firing"}, {"state": "pending"}]):
            r = self.client.get(reverse("telemetry:prometheus"))
            self.assertContains(r, "connection refused")
            self.assertContains(r, "http://a:9100/metrics")
            self.assertContains(r, "1 pending")
            r = self.client.get(reverse("telemetry:prometheus") + "?format=csv")
            self.assertIn("a:9100", r.content.decode())

    @override_settings(NAGIOS_URL="https://nagios.test/nagios")
    def test_nagios_page(self):
        self.client.force_login(self.viewer)
        with mock.patch("telemetry.nagios._urlopen", side_effect=fake_urlopen):
            r = self.client.get(reverse("telemetry:nagios"))
            self.assertContains(r, "Host Problems")
            self.assertContains(r, "CRITICAL - down")
            r = self.client.get(reverse("telemetry:nagios") + "?tab=hosts&state=unreachable")
            self.assertContains(r, ">dr<")
        cache.clear()
        with mock.patch("telemetry.nagios._urlopen", side_effect=urllib.error.URLError("refused")):
            r = self.client.get(reverse("telemetry:nagios"))
        self.assertContains(r, "Nagios unreachable")

    def test_alert_pages_and_filters(self):
        a = Alert.objects.create(fingerprint="f1", alertname="DiskFull", severity="warning", instance="db-01:9100",
                                 labels={"alertname": "DiskFull", "team": "dba"}, starts_at=timezone.now())
        Alert.objects.create(fingerprint="f2", alertname="CpuHigh", severity="critical", labels={"team": "web"})
        Alert.objects.create(fingerprint="f3", alertname="Old", status="resolved", labels={})
        self.client.force_login(self.viewer)
        r = self.client.get(reverse("telemetry:alertmanager"))
        self.assertContains(r, "DiskFull")
        self.assertContains(r, "CpuHigh")
        self.assertNotContains(r, "<b>Old</b>")
        self.assertNotContains(r, "Acknowledge selected")  # viewer
        r = self.client.get(reverse("telemetry:alertmanager") + "?label=team%3Ddba")
        self.assertContains(r, "DiskFull")
        self.assertNotContains(r, "CpuHigh</b>")
        r = self.client.get(reverse("telemetry:alertmanager") + "?label=team__contains%3Dx")  # nested lookup refused
        self.assertEqual(r.status_code, 200)
        r = self.client.get(reverse("telemetry:alertmanager") + "?tab=resolved")
        self.assertContains(r, "Old")
        r = self.client.get(reverse("telemetry:alert_detail", args=[a.pk]))
        self.assertContains(r, "am:f1")
        r = self.client.get(reverse("telemetry:alertmanager") + "?format=csv&tab=all")
        self.assertIn("DiskFull", r.content.decode())

    def test_alerts_scoped_by_site_membership(self):
        site = Site.objects.create(name="Mumbai", code="mum")
        Site.objects.create(name="DR", code="dr")
        u = User.objects.create_user("scoped")
        Membership.objects.create(user=u, site=site, role="viewer")
        Alert.objects.create(fingerprint="m", alertname="MumbaiAlert", site="Mumbai")
        dr = Alert.objects.create(fingerprint="d", alertname="DrAlert", site="DR")
        self.client.force_login(u)
        r = self.client.get(reverse("telemetry:alertmanager"))
        self.assertContains(r, "MumbaiAlert")
        self.assertNotContains(r, "DrAlert")
        self.assertEqual(self.client.get(reverse("telemetry:alert_detail", args=[dr.pk])).status_code, 404)


# ============================================================================= mutations
class MutationTests(TestCase):
    def setUp(self):
        self.viewer, self.operator, self.admin = users()
        self.alert = Alert.objects.create(fingerprint="f1", alertname="DiskFull", severity="warning", instance="db-01:9100")

    def csrf_client(self, user):
        c = Client(enforce_csrf_checks=True)
        c.force_login(user)
        c.get(reverse("telemetry:alertmanager"))
        return c, c.cookies["csrftoken"].value

    def test_acknowledge_requires_csrf(self):
        c, _tok = self.csrf_client(self.operator)
        r = c.post(reverse("telemetry:alert_ack", args=[self.alert.pk]))
        self.assertEqual(r.status_code, 403)
        self.alert.refresh_from_db()
        self.assertIsNone(self.alert.acknowledged_at)

    def test_acknowledge_requires_operate(self):
        c, tok = self.csrf_client(self.viewer)
        r = c.post(reverse("telemetry:alert_ack", args=[self.alert.pk]), {"csrfmiddlewaretoken": tok})
        self.assertEqual(r.status_code, 302)
        self.alert.refresh_from_db()
        self.assertIsNone(self.alert.acknowledged_at)
        self.assertFalse(AuditEvent.objects.filter(action="acknowledge").exists())

    def test_get_is_not_allowed(self):
        self.client.force_login(self.operator)
        self.assertEqual(self.client.get(reverse("telemetry:alert_ack", args=[self.alert.pk])).status_code, 405)

    def test_operator_acknowledges(self):
        c, tok = self.csrf_client(self.operator)
        r = c.post(reverse("telemetry:alert_ack", args=[self.alert.pk]), {"csrfmiddlewaretoken": tok, "next": "/monitoring/alerts/?tab=all"})
        self.assertRedirects(r, "/monitoring/alerts/?tab=all", fetch_redirect_response=False)
        self.alert.refresh_from_db()
        self.assertEqual(self.alert.acknowledged_by, self.operator)
        self.assertTrue(AuditEvent.objects.filter(action="acknowledge", object_id=str(self.alert.pk), actor=self.operator).exists())
        self.assertTrue(Event.objects.filter(fingerprint="am:f1", kind="ack").exists())
        r = c.post(reverse("telemetry:alert_unack", args=[self.alert.pk]), {"csrfmiddlewaretoken": tok})
        self.alert.refresh_from_db()
        self.assertIsNone(self.alert.acknowledged_at)
        self.assertTrue(AuditEvent.objects.filter(action="unacknowledge").exists())

    def test_open_redirect_refused(self):
        c, tok = self.csrf_client(self.operator)
        r = c.post(reverse("telemetry:alert_ack", args=[self.alert.pk]), {"csrfmiddlewaretoken": tok, "next": "https://evil.example/"})
        self.assertEqual(r["Location"], reverse("telemetry:alertmanager"))

    def test_bulk_acknowledge(self):
        b = Alert.objects.create(fingerprint="f2", alertname="Other")
        c, tok = self.csrf_client(self.admin)
        c.post(reverse("telemetry:alert_ack_bulk"), {"csrfmiddlewaretoken": tok, "ids": [self.alert.pk, b.pk, "x"]})
        self.assertEqual(Alert.objects.filter(acknowledged_at__isnull=False).count(), 2)
        self.assertEqual(AuditEvent.objects.filter(action="acknowledge").count(), 2)

    def test_saved_queries(self):
        c, tok = self.csrf_client(self.operator)
        url = reverse("telemetry:query_save")
        r = c.post(url, {"csrfmiddlewaretoken": tok, "name": "cpu", "promql": "up", "range": "6h", "shared": "on"})
        self.assertEqual(r.status_code, 302)
        q = SavedQuery.objects.get(name="cpu")
        self.assertEqual((q.owner, q.range_key, q.shared), (self.operator, "6h", True))
        self.assertTrue(AuditEvent.objects.filter(action="create", object_id=str(q.pk)).exists())
        c.post(url, {"csrfmiddlewaretoken": tok, "name": "cpu", "promql": "up == 0", "range": "1h"})
        q.refresh_from_db()
        self.assertEqual((q.promql, q.shared), ("up == 0", False))
        self.assertTrue(AuditEvent.objects.filter(action="update", object_id=str(q.pk)).exists())
        c.post(url, {"csrfmiddlewaretoken": tok, "name": "huge", "promql": "x" * 2001})
        self.assertFalse(SavedQuery.objects.filter(name="huge").exists())
        # viewer cannot save
        vc, vtok = self.csrf_client(self.viewer)
        vc.post(url, {"csrfmiddlewaretoken": vtok, "name": "mine", "promql": "up"})
        self.assertFalse(SavedQuery.objects.filter(name="mine").exists())
        # another operator cannot delete it; an admin can
        other = User.objects.create_user("op2", is_staff=True)
        oc, otok = self.csrf_client(other)
        oc.post(reverse("telemetry:query_delete", args=[q.pk]), {"csrfmiddlewaretoken": otok})
        self.assertTrue(SavedQuery.objects.filter(pk=q.pk).exists())
        ac, atok = self.csrf_client(self.admin)
        ac.post(reverse("telemetry:query_delete", args=[q.pk]), {"csrfmiddlewaretoken": atok})
        self.assertFalse(SavedQuery.objects.filter(pk=q.pk).exists())
        self.assertTrue(AuditEvent.objects.filter(action="delete", object_type="telemetry.savedquery").exists())

    def test_owner_deletes_own_query(self):
        q = SavedQuery.objects.create(name="mine", promql="up", owner=self.operator)
        c, tok = self.csrf_client(self.operator)
        c.post(reverse("telemetry:query_delete", args=[q.pk]), {"csrfmiddlewaretoken": tok})
        self.assertFalse(SavedQuery.objects.filter(pk=q.pk).exists())


@override_settings(PROMETHEUS_URL=PROM)
class ExplorerViewTests(TestCase):
    def setUp(self):
        self.viewer, self.operator, _admin = users()
        self.client.force_login(self.viewer)

    def test_runs_query_and_shows_last_values(self):
        rows = [{"metric": {"__name__": "up", "job": "node"}, "values": [(1.0, 1.0), (2.0, 0.0)]}]
        with mock.patch("core.prometheus.query_range", return_value=rows) as qr:
            r = self.client.get(reverse("telemetry:explorer"), {"expr": "up", "range": "24h", "step": "1s"})
        self.assertEqual(r.status_code, 200)
        args = qr.call_args[0]
        self.assertEqual(args[1], 86400)
        self.assertLessEqual(86400 // args[2] + 1, 1100)
        self.assertContains(r, 'up{job=&quot;node&quot;}')
        self.assertContains(r, "Step raised")
        self.assertContains(r, 'id="r-chart"')

    def test_policy_blocks_before_prometheus(self):
        with mock.patch("core.prometheus.query_range") as qr:
            r = self.client.get(reverse("telemetry:explorer"), {"expr": "x" * 2001})
            self.assertContains(r, "the limit is 2,000")
            r = self.client.get(reverse("telemetry:explorer"), {"expr": "up", "step": "soon"})
            self.assertContains(r, "Step must be a duration")
        qr.assert_not_called()

    def test_prometheus_error_message(self):
        with mock.patch("core.prometheus.query_range", side_effect=prometheus.PrometheusError("parse error at char 3")):
            r = self.client.get(reverse("telemetry:explorer"), {"expr": "up{"})
        self.assertContains(r, "parse error at char 3")

    def test_load_saved_query_visibility(self):
        mine = SavedQuery.objects.create(name="private", promql="node_load1", owner=self.operator)
        shared = SavedQuery.objects.create(name="team", promql="node_load5", owner=self.operator, shared=True)
        with mock.patch("core.prometheus.query_range", return_value=[]):
            r = self.client.get(reverse("telemetry:explorer"), {"saved": shared.pk})
            self.assertContains(r, "node_load5")
            r = self.client.get(reverse("telemetry:explorer"), {"saved": mine.pk})
        self.assertNotContains(r, "node_load1</textarea>")
        self.assertContains(r, "not shared with you")


# ============================================================================= jobs / seed
class JobAndSeedTests(TestCase):
    def test_job_registered(self):
        self.assertIn("telemetry.prune_alerts", core_jobs.JOBS)

    @override_settings(TELEMETRY_ALERT_RETENTION_DAYS=30)
    def test_prune_keeps_firing_and_recent(self):
        old = timezone.now() - timedelta(days=40)
        Alert.objects.create(fingerprint="a", alertname="A", status="resolved", last_received_at=old)
        Alert.objects.create(fingerprint="b", alertname="B", status="firing", last_received_at=old)
        Alert.objects.create(fingerprint="c", alertname="C", status="resolved")
        self.assertEqual(core_jobs.JOBS["telemetry.prune_alerts"]["func"](), "pruned 1 resolved alert(s)")
        self.assertEqual(sorted(Alert.objects.values_list("fingerprint", flat=True)), ["b", "c"])

    def test_job_never_raises(self):
        from . import jobs
        with mock.patch("telemetry.alerts.prune", side_effect=RuntimeError("db gone")), \
                self.assertLogs("linkedeye.telemetry", "ERROR"):
            self.assertEqual(jobs.prune_alerts(), "error")

    def test_seed_is_idempotent_and_marked(self):
        out = io.StringIO()
        call_command("seed_telemetry", stdout=out)
        call_command("seed_telemetry", stdout=out)
        self.assertEqual(Alert.objects.count(), 5)
        self.assertTrue(all(a.is_example for a in Alert.objects.all()))
        self.assertEqual(SavedQuery.objects.filter(name__startswith="Example: ").count(), 4)
        self.assertFalse(Event.objects.filter(source="telemetry").exists())
        call_command("seed_telemetry", "--remove", stdout=out)
        self.assertEqual(Alert.objects.count(), 0)
        self.assertEqual(SavedQuery.objects.count(), 0)


# ============================================================================= adversarial QA regressions
class QaRegressionTests(PromMixin, TestCase):
    """Bugs found by the end-to-end QA pass; each test failed before its fix."""

    def setUp(self):
        cache.clear()
        self.viewer, self.operator, self.admin = users()

    def test_label_filter_does_not_crash_on_sqlite(self):
        # KeyTextTransform kept the JSON "exact" lookup -> JSON('dba') -> "malformed JSON" -> HTTP 500
        Alert.objects.create(fingerprint="l1", alertname="DiskFull", labels={"team": "dba", "contains": "x"})
        Alert.objects.create(fingerprint="l2", alertname="CpuHigh", labels={"team": "web"})
        self.client.force_login(self.viewer)
        r = self.client.get(reverse("telemetry:alertmanager") + "?tab=all&label=team%3Ddba")
        self.assertEqual(r.status_code, 200)
        self.assertEqual([a.alertname for a in r.context["page"]], ["DiskFull"])
        r = self.client.get(reverse("telemetry:alertmanager") + "?tab=all&label=contains%3Dx")  # a lookup-named label
        self.assertEqual([a.alertname for a in r.context["page"]], ["DiskFull"])
        r = self.client.get(reverse("telemetry:alertmanager") + "?tab=all&label=team%3Dnobody")
        self.assertEqual(len(r.context["page"]), 0)

    def test_remove_label_link_keeps_other_filters(self):
        Alert.objects.create(fingerprint="l1", alertname="DiskFull", severity="critical", labels={"team": "dba"})
        self.client.force_login(self.viewer)
        r = self.client.get(reverse("telemetry:alertmanager") + "?tab=all&severity=critical&label=team%3Ddba&page=1")
        self.assertContains(r, 'href="?tab=all&amp;severity=critical" title="Remove label filter"')

    @override_settings(PROMETHEUS_URL=PROM)
    def test_host_detail_alerts_are_site_scoped(self):
        # a host without a CMDB CI is global, but its alerts carry their own site: a Mumbai-only viewer
        # must not see the DR alert on the host page (the alert list and detail already 404 for it)
        mum = Site.objects.create(name="Mumbai", code="mum")
        Site.objects.create(name="DR", code="dr")
        u = User.objects.create_user("mumviewer")
        Membership.objects.create(user=u, site=mum, role="viewer")
        Alert.objects.create(fingerprint="a-dr", alertname="DrOnlyAlert", instance="db-01:9100", site="DR")
        Alert.objects.create(fingerprint="a-mum", alertname="MumbaiAlert", instance="db-01:9100", site="Mumbai")
        self.start_prom()
        self.client.force_login(u)
        r = self.client.get(reverse("telemetry:host_detail", args=["db-01:9100"]))
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "MumbaiAlert")
        self.assertNotContains(r, "DrOnlyAlert")
        self.client.force_login(self.admin)
        self.assertContains(self.client.get(reverse("telemetry:host_detail", args=["db-01:9100"])), "DrOnlyAlert")

    @override_settings(NAGIOS_URL="https://nagios.test/nagios")
    def test_nagios_non_object_json_is_an_error_not_a_500(self):
        self.client.force_login(self.viewer)
        for body in (b"[1, 2, 3]", b'"hello"', b'{"result": "oops", "data": []}'):
            cache.clear()
            with mock.patch("telemetry.nagios._urlopen", return_value=FakeResp(body)):
                with self.assertRaises(nagios.NagiosError):
                    nagios.fetch_status()
            cache.clear()
            with mock.patch("telemetry.nagios._urlopen", return_value=FakeResp(body)):
                r = self.client.get(reverse("telemetry:nagios"))
            self.assertEqual(r.status_code, 200, body)
            self.assertContains(r, "Nagios query failed")

    @override_settings(NAGIOS_URL="https://nagios.test/nagios")
    def test_nagios_odd_values_do_not_crash(self):
        def odd(req, timeout=None):
            if "hostlist" in req.full_url:
                data = {"hostlist": {"h1": {"name": 5, "status": "down"}, "h2": None}}
            else:
                data = {"servicelist": {"h1": {"s": {"status": 16, "description": 7, "host_name": 9}}}}
            return FakeResp(json.dumps({"result": "not-a-dict", "data": data}).encode())
        with mock.patch("telemetry.nagios._urlopen", side_effect=odd):
            st = nagios.fetch_status()
        self.assertEqual({h["name"] for h in st["hosts"]}, {"5", "h2"})
        self.assertEqual(st["services"][0]["service"], "7")
        self.client.force_login(self.viewer)
        self.assertEqual(self.client.get(reverse("telemetry:nagios")).status_code, 200)

    @override_settings(ALERTMANAGER_WEBHOOK_TOKEN=TOKEN, INCIDENT_AUTO_CREATE=False)
    def test_concurrent_insert_of_same_fingerprint_is_retried_as_update(self):
        # Alertmanager HA peers deliver the same notification in parallel: the peer's INSERT lands between our
        # SELECT ... FOR UPDATE (no row yet) and our INSERT -> IntegrityError, previously an HTTP 500
        Alert.objects.create(fingerprint="race1", alertname="HostDown", status="firing", severity="critical",
                             instance="db-01:9100", fire_count=1)
        real = Alert.objects.select_for_update
        calls = {"n": 0}

        def first_blind(*a, **k):
            calls["n"] += 1
            return Alert.objects.none() if calls["n"] == 1 else real(*a, **k)
        with mock.patch.object(Alert.objects, "select_for_update", side_effect=first_blind):
            r = self.client.post("/api/v1/alertmanager/", data=json.dumps(am_payload(am_alert(fp="race1"))),
                                 content_type="application/json", HTTP_AUTHORIZATION=f"Bearer {TOKEN}")
        self.assertEqual(r.status_code, 200, r.content)
        self.assertEqual(r.json()["created"], 0)
        self.assertEqual(r.json()["updated"], 1)
        self.assertEqual(r.json()["events"], 0)  # still firing, same severity: no duplicate event
        self.assertEqual(Alert.objects.filter(fingerprint="race1").count(), 1)

    @override_settings(PROMETHEUS_URL=PROM)
    def test_non_prometheus_responses_become_prometheus_errors(self):
        from . import promapi
        with mock.patch("core.prometheus.query", side_effect=ValueError("Expecting value")):
            with self.assertRaisesRegex(prometheus.PrometheusError, "unexpected response"):
                promapi.query("up")
        with mock.patch("core.prometheus.targets", return_value="not a list"):
            with self.assertRaises(prometheus.PrometheusError):
                promapi.targets()
        with mock.patch("core.prometheus.query", side_effect=TypeError("'NoneType' object is not subscriptable")):
            self.client.force_login(self.viewer)
            r = self.client.get(reverse("telemetry:infrastructure"))
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "unexpected response")

    def test_nagios_auth_header_not_forwarded_cross_origin(self):
        import urllib.request
        h = nagios._SameOriginAuthRedirect()
        req = urllib.request.Request("https://nagios.test/nagios/cgi-bin/statusjson.cgi")
        req.add_header("Authorization", "Basic abc")
        same = h.redirect_request(req, None, 302, "Found", {}, "https://nagios.test/other")
        other = h.redirect_request(req, None, 302, "Found", {}, "http://evil.test/x")
        self.assertEqual(same.get_header("Authorization"), "Basic abc")
        self.assertIsNone(other.get_header("Authorization"))
