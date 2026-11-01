import socket
import threading
from datetime import timedelta
from io import StringIO
from unittest import mock

from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.management import call_command
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from core import jobs as core_jobs
from core import prometheus
from core.models import AuditEvent, Event, Membership, Site

from . import discovery, jobs, metrics, probe, services
from .models import Device, DevicePoll, DiscoveredHost, DiscoveryRun, Interface, validate_host
from .probe import TcpResult

T = "default"
LIST_URLS = ["network:switches", "network:routers", "network:firewalls", "network:load_balancers", "network:wireless",
             "network:physical_servers", "network:virtual_machines", "network:all"]


def dev(name="sw-01", **kw):
    kw.setdefault("tenant_key", T)
    kw.setdefault("mgmt_ip", "192.0.2.10")
    kw.setdefault("device_type", "switch")
    return Device.objects.create(name=name, **kw)


def ok(ms=1.5):
    return TcpResult(True, ms, ip="192.0.2.10")


def fail(msg="Connection refused on port 22"):
    return TcpResult(False, error=msg, ip="192.0.2.10")


def blocked():
    return TcpResult(False, error="Blocked by probe policy: x", blocked=True)


def users():
    viewer = User.objects.create_user("viewer", password="pw")
    operator = User.objects.create_user("operator", password="pw", is_staff=True)
    admin = User.objects.create_superuser("admin", "a@example.com", "pw")
    return viewer, operator, admin


def prom_row(value, **labels):
    return {"metric": labels, "value": value}


# ---------------------------------------------------------------------------------------------- models
@override_settings(LINKEDEYE_TENANT=T)
class ModelTests(TestCase):
    def test_validate_host(self):
        for good in ("10.0.0.1", "2001:db8::1", "core-sw-01", "fw.example.com"):
            validate_host(good)
        for bad in ("", "bad host", "-x", "1.2.3", "http://x"):
            with self.assertRaises(ValidationError, msg=bad):
                validate_host(bad)

    def test_properties(self):
        d = dev(tags="example, Core ,", uptime_seconds=86 * 86400 + 4 * 3600 + 120, device_type="firewall")
        self.assertEqual(d.tag_list, ["example", "Core"])
        self.assertTrue(d.is_example)
        self.assertEqual(d.uptime_display, "86 days, 4 hours")
        self.assertEqual(d.uptime_short, "86 days")
        d.uptime_seconds = 3 * 3600 + 5 * 60
        self.assertEqual(d.uptime_short, "3 h 5 min")
        self.assertEqual(d.type_list_url, reverse("network:firewalls"))
        self.assertEqual(d.get_absolute_url(), reverse("network:detail", args=[d.pk]))
        self.assertEqual(d.status, "unknown")

    def test_name_unique_per_tenant(self):
        dev("a")
        dev("a", tenant_key="other")
        from django.db import IntegrityError, transaction
        with self.assertRaises(IntegrityError), transaction.atomic():
            dev("a")

    def test_interface_tone_and_run_progress(self):
        d = dev()
        i = Interface.objects.create(device=d, if_index=1, name="Gi1", utilization=90)
        self.assertEqual(i.util_tone, "crit")
        i.utilization = 65
        self.assertEqual(i.util_tone, "warn")
        i.utilization = None
        self.assertEqual(i.util_tone, "mute")
        run = DiscoveryRun(cidr="192.0.2.0/30", ports="22, 443,x", total_addresses=4, scanned=1, skipped=1)
        self.assertEqual(run.port_list, [22, 443])
        self.assertEqual(run.progress, 50)
        self.assertTrue(run.active)


# ---------------------------------------------------------------------------------------------- probe
class ProbeTests(TestCase):
    def test_private_address_blocked_without_allow_list(self):
        with override_settings(PROBE_ALLOWED_PRIVATE_CIDRS=[]):
            r = probe.tcp_probe("10.1.2.3", 22, 1)
        self.assertFalse(r.ok)
        self.assertTrue(r.blocked)
        self.assertIn("Blocked by probe policy", r.error)

    def test_metadata_address_always_blocked(self):
        with override_settings(PROBE_ALLOWED_PRIVATE_CIDRS=["0.0.0.0/0"]):
            self.assertTrue(probe.tcp_probe("169.254.169.254", 80, 1).blocked)
            self.assertFalse(probe.allowed("169.254.169.254"))

    @override_settings(PROBE_ALLOWED_PRIVATE_CIDRS=["127.0.0.0/8"])
    def test_connect_open_and_closed_port(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            r = probe.tcp_probe("127.0.0.1", port, 2)
            self.assertTrue(r.ok, r.error)
            self.assertIsNotNone(r.latency_ms)
        finally:
            srv.close()
        r = probe.tcp_probe("127.0.0.1", port, 2)  # nothing listens any more
        self.assertFalse(r.ok)
        self.assertFalse(r.blocked)

    def test_dns_failure(self):
        with mock.patch("probes.checks.resolve", side_effect=socket.gaierror(-2, "Name or service not known")):
            r = probe.tcp_probe("no-such-host.invalid", 22, 1)
        self.assertFalse(r.ok)
        self.assertIn("DNS resolution failed", r.error)


# ---------------------------------------------------------------------------------------------- reachability job
@override_settings(LINKEDEYE_TENANT=T)
class ReachabilityTests(TestCase):
    def test_unknown_to_down_emits_critical_event(self):
        d = dev()
        jobs.record(d, fail())
        d.refresh_from_db()
        self.assertEqual(d.status, "down")
        ev = Event.objects.get(source="network")
        self.assertEqual((ev.severity, ev.fingerprint, ev.object_id), ("critical", f"network:{d.pk}", str(d.pk)))
        self.assertEqual(ev.data["device_type"], "switch")
        self.assertEqual(DevicePoll.objects.get(device=d).status, "down")

    def test_up_device_needs_two_failures_then_recovers(self):
        d = dev()
        jobs.record(d, ok(2.0))
        d.refresh_from_db()
        self.assertEqual((d.status, d.last_latency_ms), ("up", 2.0))
        self.assertIsNotNone(d.last_seen)
        self.assertEqual(Event.objects.filter(source="network").count(), 0)  # unknown -> up is not an alert
        jobs.record(d, fail())
        self.assertEqual(d.status, "up")
        self.assertEqual(d.consecutive_failures, 1)
        self.assertEqual(Event.objects.filter(source="network").count(), 0)
        jobs.record(d, fail())
        self.assertEqual(d.status, "down")
        self.assertEqual(Event.objects.filter(source="network", severity="critical").count(), 1)
        jobs.record(d, fail())  # still down: no new event
        self.assertEqual(Event.objects.filter(source="network").count(), 1)
        jobs.record(d, ok())
        self.assertEqual(d.status, "up")
        rec = Event.objects.get(source="network", severity="ok")
        self.assertEqual(rec.fingerprint, f"network:{d.pk}")
        self.assertEqual(DevicePoll.objects.filter(device=d).count(), 5)

    def test_blocked_by_policy_is_unknown_without_event(self):
        d = dev()
        jobs.record(d, blocked())
        d.refresh_from_db()
        self.assertEqual(d.status, "unknown")
        self.assertIn("probe policy", d.last_error)
        self.assertEqual(Event.objects.filter(source="network").count(), 0)

    def test_poll_devices_job_skips_disabled_and_never_raises(self):
        a, b = dev("a"), dev("b", enabled=False)
        with mock.patch("network.probe.tcp_probe", return_value=ok()) as tp:
            summary = jobs.poll_devices()
        self.assertEqual(tp.call_count, 1)
        self.assertIn("polled 1", summary)
        a.refresh_from_db()
        b.refresh_from_db()
        self.assertEqual((a.status, b.status), ("up", "unknown"))
        with mock.patch("network.jobs.check_devices", side_effect=RuntimeError("boom")), self.assertLogs("linkedeye.network", "ERROR"):
            self.assertEqual(jobs.poll_devices(), "error")

    def test_prune_old_polls(self):
        d = dev()
        DevicePoll.objects.create(device=d, status="up", checked_at=timezone.now() - timedelta(days=400))
        DevicePoll.objects.create(device=d, status="up")
        jobs._state["last_prune"] = None
        self.assertEqual(jobs._maybe_prune(), 1)
        self.assertEqual(DevicePoll.objects.count(), 1)

    def test_jobs_registered(self):
        for name in ("network.reachability", "network.metrics", "network.discovery"):
            self.assertIn(name, core_jobs.JOBS)
        self.assertEqual(core_jobs.JOBS["network.reachability"]["interval"], 60)

    def test_availability_and_charts(self):
        d = dev()
        for st in ("up", "up", "up", "down", "unknown"):
            DevicePoll.objects.create(device=d, status=st, latency_ms=3.0 if st == "up" else None)
        self.assertEqual(services.availability([d.pk])[d.pk], 75.0)
        chart = services.availability_chart(d)
        self.assertEqual(sum(chart["series"][0]["values"]), 3)
        self.assertEqual(sum(chart["series"][1]["values"]), 1)
        self.assertEqual(services.latency_chart(d)["series"][0]["values"][-1], 3.0)
        self.assertIsNone(services.availability_chart(dev("empty", mgmt_ip="192.0.2.11")))


# ---------------------------------------------------------------------------------------------- metrics job
def fake_query(promql):
    """Prometheus answers shaped like snmp_exporter IF-MIB output for instance 'sw1'."""
    base = {"instance": "sw1", "job": "snmp"}
    ifs = [("1", "Gi1/0/1", "Uplink"), ("2", "Gi1/0/2", "")]
    if "ifHCInOctets" in promql:
        return [prom_row(400.0, ifIndex=i, ifName=n, ifAlias=a, **base) for i, n, a in ifs]
    if "ifHCOutOctets" in promql:
        return [prom_row(100.0, ifIndex=i, ifName=n, **base) for i, n, a in ifs]
    if "ifOperStatus" in promql:
        return [prom_row(1, ifIndex="1", **base), prom_row(2, ifIndex="2", **base)]
    if "ifAdminStatus" in promql:
        return [prom_row(1, ifIndex="1", **base), prom_row(1, ifIndex="2", **base)]
    if "ifHighSpeed" in promql:
        return [prom_row(1000, ifIndex=i, **base) for i, n, a in ifs]
    if "ifType" in promql:
        return [prom_row(1, ifIndex="1", ifType="ethernetCsmacd", **base), prom_row(161, ifIndex="2", **base)]
    if "sysUpTime" in promql:
        return [prom_row(7444800.0, **base), prom_row(5.0, instance="other")]
    return []


@override_settings(LINKEDEYE_TENANT=T, PROMETHEUS_URL="http://prometheus.test:9090")
class MetricsTests(TestCase):
    def test_regex_and_string_escaping(self):
        self.assertEqual(metrics.regex_alternation(["10.0.0.1:161", "sw-1"]), r"10\\.0\\.0\\.1:161|sw-1")
        self.assertEqual(metrics.promql_string('a"b\\c'), 'a\\"b\\\\c')

    def test_fetch_and_apply(self):
        d = dev(prometheus_instance="sw1")
        with mock.patch("core.prometheus.query", side_effect=fake_query):
            summary = jobs.collect_metrics()
        self.assertEqual(summary, "metrics for 1 device(s)")
        d.refresh_from_db()
        self.assertEqual(d.uptime_seconds, 7444800)
        self.assertEqual(d.metrics_error, "")
        self.assertIsNotNone(d.metrics_updated_at)
        g1, g2 = d.interfaces.order_by("if_index")
        self.assertEqual((g1.name, g1.alias, g1.if_type, g1.oper_status, g1.admin_status), ("Gi1/0/1", "Uplink", "Ethernet", "up", "up"))
        self.assertEqual((g1.in_mbps, g1.out_mbps, g1.speed_mbps, g1.utilization), (400.0, 100.0, 1000.0, 40.0))
        self.assertEqual((g2.oper_status, g2.if_type), ("down", "LAG"))

    def test_interface_transition_event_and_removed_interfaces(self):
        d = dev(prometheus_instance="sw1")
        Interface.objects.create(device=d, if_index=2, name="Gi1/0/2", oper_status="up", admin_status="up")
        Interface.objects.create(device=d, if_index=99, name="gone")
        with mock.patch("core.prometheus.query", side_effect=fake_query):
            jobs.collect_metrics()
        self.assertFalse(d.interfaces.filter(if_index=99).exists())
        ev = Event.objects.get(source="network")
        self.assertEqual((ev.severity, ev.fingerprint), ("warning", f"network:{d.pk}:if2"))

    def test_missing_series_and_errors_are_tolerated(self):
        d = dev(prometheus_instance="sw1")
        Interface.objects.create(device=d, if_index=1, name="Gi1", in_mbps=5, out_mbps=5, utilization=1)
        with mock.patch("core.prometheus.query", side_effect=prometheus.PrometheusError("Prometheus unreachable: refused")):
            jobs.collect_metrics()
        d.refresh_from_db()
        self.assertIn("No snmp_exporter series", d.metrics_error)
        self.assertIn("unreachable", d.metrics_error)
        i = d.interfaces.get()
        self.assertIsNone(i.in_mbps)  # stale numbers are not shown as current

        def partial(q):
            if "ifHCInOctets" in q:
                raise prometheus.PrometheusError("timeout")
            return fake_query(q)
        with mock.patch("core.prometheus.query", side_effect=partial):
            jobs.collect_metrics()
        d.refresh_from_db()
        self.assertTrue(d.metrics_error.startswith("Partial data"))
        self.assertIsNone(d.interfaces.get(if_index=1).in_mbps)
        self.assertEqual(d.interfaces.get(if_index=1).out_mbps, 100.0)

    @override_settings(PROMETHEUS_URL="")
    def test_not_configured(self):
        dev(prometheus_instance="sw1")
        with mock.patch("core.prometheus.query") as q:
            self.assertIsNone(jobs.collect_metrics())
        q.assert_not_called()
        chart, msg = metrics.traffic_range(Device.objects.get())
        self.assertIsNone(chart)
        self.assertIn("LINKEDEYE_PROMETHEUS_URL", msg)

    def test_traffic_range(self):
        d = dev()
        self.assertIn("Prometheus instance", metrics.traffic_range(d)[1])
        d.prometheus_instance = "sw1"
        now = timezone.now().timestamp()
        series = [{"metric": {}, "values": [(now - 60, 10.0), (now, 12.5)]}]
        with mock.patch("core.prometheus.query_range", return_value=series) as qr:
            chart, msg = metrics.traffic_range(d)
        self.assertEqual(msg, "")
        self.assertIn('instance="sw1"', qr.call_args[0][0])
        self.assertEqual(chart["series"][0]["values"], [10.0, 12.5])
        with mock.patch("core.prometheus.query_range", return_value=[]):
            self.assertIn("No interface counters", metrics.traffic_range(d)[1])
        with mock.patch("core.prometheus.query_range", side_effect=prometheus.PrometheusError("HTTP 500")):
            self.assertIn("HTTP 500", metrics.traffic_range(d)[1])


# ---------------------------------------------------------------------------------------------- discovery
@override_settings(LINKEDEYE_TENANT=T, PROBE_ALLOWED_PRIVATE_CIDRS=["192.0.2.0/24"])
class DiscoveryTests(TestCase):
    def test_parse_limits(self):
        self.assertEqual(str(discovery.parse_cidr("192.0.2.17/24")), "192.0.2.0/24")
        for bad in ("10.0.0.0/23", "nonsense", "2001:db8::/64"):
            with self.assertRaises(ValidationError):
                discovery.parse_cidr(bad)
        self.assertEqual(discovery.parse_ports("22, 443 22"), [22, 443])
        for bad in ("", "0", "70000", "a", ",".join(str(p) for p in range(1, 13))):
            with self.assertRaises(ValidationError):
                discovery.parse_ports(bad)
        self.assertEqual(discovery.addresses(discovery.parse_cidr("192.0.2.5/32")), ["192.0.2.5"])
        self.assertEqual(len(discovery.addresses(discovery.parse_cidr("192.0.2.0/24"))), 254)

    def test_policy_split(self):
        with override_settings(PROBE_ALLOWED_PRIVATE_CIDRS=["192.0.2.0/30"]):
            allowed, blocked = discovery.split_allowed(discovery.addresses(discovery.parse_cidr("192.0.2.0/29")))
        self.assertEqual(allowed, ["192.0.2.1", "192.0.2.2", "192.0.2.3"])
        self.assertEqual(len(blocked), 3)

    def test_execute_records_hosts_and_existing_devices(self):
        existing = dev("known", mgmt_ip="192.0.2.2")
        run = DiscoveryRun.objects.create(tenant_key=T, cidr="192.0.2.0/29", ports="22,443")
        answers = {"192.0.2.1": ([22], 1.2), "192.0.2.2": ([443], 3.0)}

        def fake_scan(ip, ports, timeout=None):
            ports_open, ms = answers.get(ip, ([], None))
            return ip, ports_open, ms
        with override_settings(PROBE_ALLOWED_PRIVATE_CIDRS=["192.0.2.0/30"]), mock.patch("network.discovery.scan_host", side_effect=fake_scan) as scan:
            discovery.execute(run.pk)
        run.refresh_from_db()
        self.assertEqual(scan.call_count, 3)   # only policy-allowed addresses are contacted
        self.assertEqual((run.status, run.total_addresses, run.scanned, run.skipped, run.found), ("done", 6, 3, 3, 2))
        h1 = run.hosts.get(ip="192.0.2.1")
        self.assertEqual((h1.status, h1.open_ports, h1.latency_ms), ("new", [22], 1.2))
        h2 = run.hosts.get(ip="192.0.2.2")
        self.assertEqual((h2.status, h2.device), ("existing", existing))
        self.assertTrue(AuditEvent.objects.filter(action="discovery_finished", object_id=str(run.pk)).exists())
        self.assertIsNone(discovery.execute(run.pk))  # already claimed: idempotent

    def test_scan_host_uses_policy_and_connect(self):
        with mock.patch("network.probe.connect", side_effect=lambda ip, port, t: TcpResult(port == 443, 2.0 if port == 443 else None)):
            self.assertEqual(discovery.scan_host("192.0.2.9", [22, 443]), ("192.0.2.9", [443], 2.0))
        with mock.patch("network.probe.connect") as conn:
            self.assertEqual(discovery.scan_host("169.254.169.254", [80]), ("169.254.169.254", [], None))
        conn.assert_not_called()

    def test_failed_and_cancelled_runs(self):
        run = DiscoveryRun.objects.create(tenant_key=T, cidr="10.0.0.0/8", ports="22")
        discovery.execute(run.pk)
        run.refresh_from_db()
        self.assertEqual(run.status, "failed")
        self.assertIn("too large", run.error)

        run = DiscoveryRun.objects.create(tenant_key=T, cidr="192.0.2.0/24", ports="22")

        def cancelled(pk):
            DiscoveryRun.objects.filter(pk=pk).update(status="cancelled")
            return True
        with mock.patch("network.discovery.scan_host", side_effect=lambda ip, ports, timeout=None: (ip, [], None)), \
                mock.patch("network.discovery._cancelled", side_effect=cancelled), mock.patch.object(discovery, "SCAN_WORKERS", 1):
            discovery.execute(run.pk)
        run.refresh_from_db()
        self.assertEqual(run.status, "cancelled")
        self.assertLess(run.scanned, 254)

    def test_tick_launches_queued_and_fails_stale(self):
        old = timezone.now() - timedelta(minutes=1)
        queued = DiscoveryRun.objects.create(tenant_key=T, cidr="192.0.2.0/30", created_at=old)
        DiscoveryRun.objects.create(tenant_key=T, cidr="192.0.2.0/30")  # too fresh: its own thread will start it
        stale = DiscoveryRun.objects.create(tenant_key=T, cidr="192.0.2.0/30", status="running",
                                            started_at=timezone.now() - timedelta(hours=1))
        launched = []
        summary = discovery.tick(launcher=launched.append)
        self.assertEqual([r.pk for r in launched], [queued.pk])
        stale.refresh_from_db()
        self.assertEqual(stale.status, "failed")
        self.assertIn("started 1, failed 1", summary)

    def test_launch_runs_in_background_thread(self):
        run = DiscoveryRun.objects.create(tenant_key=T, cidr="192.0.2.0/30")
        with mock.patch("network.discovery.execute") as ex, mock.patch("network.discovery.connection"):
            t = discovery.launch(run)
            t.join(5)
        self.assertIsInstance(t, threading.Thread)
        ex.assert_called_once_with(run.pk)


# ---------------------------------------------------------------------------------------------- views
@override_settings(LINKEDEYE_TENANT=T, PROMETHEUS_URL="")
class ViewTests(TestCase):
    def setUp(self):
        self.viewer, self.operator, self.admin = users()
        self.d = dev("core-sw-01", site="Mumbai (NSE)", vendor="Cisco", model="C9500", prometheus_instance="sw1")
        self.fw = dev("FG-01", device_type="firewall", mgmt_ip="192.0.2.254", site="DR Site", vendor="Fortinet")
        self.c = Client()

    def login(self, user):
        self.c.force_login(user)

    def test_login_required(self):
        r = self.c.get(reverse("network:all"))
        self.assertEqual(r.status_code, 302)
        self.assertIn("/accounts/login/", r["Location"])

    def test_viewer_sees_all_pages(self):
        self.login(self.viewer)
        for name in LIST_URLS:
            r = self.c.get(reverse(name))
            self.assertEqual(r.status_code, 200, name)
        r = self.c.get(reverse("network:firewalls"))
        self.assertContains(r, "FG-01")
        self.assertNotContains(r, "core-sw-01")
        self.assertNotContains(r, "Add Device")
        r = self.c.get(reverse("network:all") + "?status=unknown&q=core")
        self.assertContains(r, "core-sw-01")
        self.assertNotContains(r, ">FG-01<")
        for tab in ("overview", "interfaces", "traffic", "events", "configuration"):
            r = self.c.get(reverse("network:detail", args=[self.d.pk]) + f"?tab={tab}")
            self.assertEqual(r.status_code, 200, tab)
            self.assertContains(r, "core-sw-01")
        r = self.c.get(reverse("network:detail", args=[self.d.pk]))
        self.assertContains(r, "No metrics source: set LINKEDEYE_PROMETHEUS_URL and the device Prometheus instance.")
        self.assertNotContains(r, "Sessions")
        self.assertNotContains(r, "Threats")
        self.assertNotContains(r, reverse("network:edit", args=[self.d.pk]))
        self.assertEqual(self.c.get(reverse("network:discovery")).status_code, 200)

    def test_detail_with_data(self):
        Interface.objects.create(device=self.d, if_index=1, name="Gi1/0/1", alias="Uplink", oper_status="up", admin_status="up",
                                 speed_mbps=1000, in_mbps=680, out_mbps=520, utilization=68)
        jobs.record(self.d, fail("Timed out after 5s connecting to port 22"))
        self.d.uptime_seconds = 86 * 86400
        self.d.save()
        self.login(self.viewer)
        r = self.c.get(reverse("network:detail", args=[self.d.pk]))
        self.assertContains(r, "Gi1/0/1")
        self.assertContains(r, "68%")
        self.assertContains(r, "86 days")
        self.assertContains(r, "core-sw-01 is down")
        self.assertContains(r, "Timed out after 5s")
        r = self.c.get(reverse("network:detail", args=[self.d.pk]) + "?tab=events")
        self.assertContains(r, "Check History")
        r = self.c.get(reverse("network:interfaces_export", args=[self.d.pk]))
        self.assertIn("Gi1/0/1,Uplink", r.content.decode())

    def test_topology_link_uses_cmdb_ci(self):
        self.login(self.viewer)
        try:
            from cmdb.models import ConfigurationItem
        except Exception:  # noqa: BLE001 - CMDB app absent
            self.skipTest("cmdb not installed")
        ci = ConfigurationItem.objects.create(tenant_key=T, name="core-sw-01", ci_type="network_device")
        r = self.c.get(reverse("network:detail", args=[self.d.pk]))
        self.assertContains(r, f"{reverse('cmdb:topology')}?root={ci.pk}")

    def test_csv_export(self):
        self.login(self.viewer)
        r = self.c.get(reverse("network:export") + "?type=firewall")
        self.assertEqual(r["Content-Type"], "text/csv; charset=utf-8")
        body = r.content.decode()
        self.assertIn("FG-01,firewall,Fortinet", body)
        self.assertNotIn("core-sw-01", body)

    def test_viewer_cannot_mutate(self):
        self.login(self.viewer)
        self.assertEqual(self.c.get(reverse("network:create")).status_code, 403)
        r = self.c.post(reverse("network:create"), {"name": "x", "device_type": "switch", "mgmt_ip": "192.0.2.1", "check_port": 22})
        self.assertEqual(r.status_code, 302)
        self.assertFalse(Device.objects.filter(name="x").exists())
        r = self.c.post(reverse("network:check", args=[self.d.pk]), HTTP_ACCEPT="application/json")
        self.assertEqual(r.status_code, 403)
        self.c.post(reverse("network:delete", args=[self.d.pk]))
        self.assertTrue(Device.objects.filter(pk=self.d.pk).exists())
        self.c.post(reverse("network:discovery"), {"cidr": "192.0.2.0/30", "ports": "22"})
        self.assertFalse(DiscoveryRun.objects.exists())
        self.assertFalse(AuditEvent.objects.exists())

    def test_operator_create_edit_check(self):
        self.login(self.operator)
        self.assertEqual(self.c.get(reverse("network:create") + "?type=router").status_code, 200)
        data = {"name": "edge-rtr-01", "device_type": "router", "vendor": "Juniper", "mgmt_ip": " 198.51.100.1 ", "check_port": 22,
                "site": "", "environment": "prod", "tags": "edge, edge, wan", "enabled": "on"}
        with mock.patch("network.probe.tcp_probe", return_value=ok(4.0)):
            r = self.c.post(reverse("network:create"), data)
        d = Device.objects.get(name="edge-rtr-01")
        self.assertRedirects(r, d.get_absolute_url())
        self.assertEqual((d.mgmt_ip, d.tags, d.status, d.tenant_key), ("198.51.100.1", "edge, wan", "up", T))
        self.assertTrue(AuditEvent.objects.filter(action="create", object_type="network.device", object_id=str(d.pk)).exists())

        r = self.c.post(reverse("network:create"), dict(data, name="EDGE-RTR-01"))
        self.assertContains(r, "already exists")
        r = self.c.post(reverse("network:create"), dict(data, name="bad", mgmt_ip="not a host"))
        self.assertContains(r, "Enter an IP address or a hostname.")

        r = self.c.post(reverse("network:edit", args=[d.pk]), dict(data, model="MX204"))
        self.assertRedirects(r, d.get_absolute_url())
        d.refresh_from_db()
        self.assertEqual(d.model, "MX204")
        upd = AuditEvent.objects.get(action="update", object_id=str(d.pk))
        self.assertIn("model", upd.details["changed"])

        # changing the Prometheus instance drops the previous target's interfaces; disabling clears the status
        Interface.objects.create(device=d, if_index=1, name="ge-0/0/0")
        d.status = "down"
        d.save()
        edit = dict(data, model="MX204", prometheus_instance="edge-rtr-01")
        edit.pop("enabled")
        self.c.post(reverse("network:edit", args=[d.pk]), edit)
        d.refresh_from_db()
        self.assertEqual((d.status, d.enabled, d.interfaces.count()), ("unknown", False, 0))

        with mock.patch("network.probe.tcp_probe", return_value=fail()):
            r = self.c.post(reverse("network:check", args=[self.d.pk]), HTTP_ACCEPT="application/json")
        self.assertEqual(r.json()["status"], "down")
        self.assertTrue(AuditEvent.objects.filter(action="run", object_id=str(self.d.pk)).exists())
        with mock.patch("network.probe.tcp_probe", return_value=ok()):
            r = self.c.post(reverse("network:check", args=[self.d.pk]), {"next": "/network/devices/"})
        self.assertRedirects(r, "/network/devices/")
        with mock.patch("network.probe.tcp_probe", return_value=ok()) as tp:
            r = self.c.post(reverse("network:check_all"), {"type": "firewall"})
        self.assertEqual(tp.call_count, 1)
        self.assertEqual(r.status_code, 302)

    def test_operator_cannot_delete_admin_can(self):
        self.login(self.operator)
        self.c.post(reverse("network:delete", args=[self.d.pk]))
        self.assertTrue(Device.objects.filter(pk=self.d.pk).exists())
        self.login(self.admin)
        r = self.c.post(reverse("network:delete", args=[self.d.pk]))
        self.assertRedirects(r, reverse("network:switches"))
        self.assertFalse(Device.objects.filter(pk=self.d.pk).exists())
        a = AuditEvent.objects.get(action="delete")
        self.assertEqual(a.details["name"], "core-sw-01")
        self.assertEqual(self.c.get(reverse("network:delete", args=[self.fw.pk])).status_code, 405)

    def test_csrf_enforced(self):
        c = Client(enforce_csrf_checks=True)
        c.force_login(self.admin)
        self.assertEqual(c.post(reverse("network:delete", args=[self.d.pk])).status_code, 403)
        self.assertEqual(c.post(reverse("network:check", args=[self.d.pk])).status_code, 403)
        self.assertTrue(Device.objects.filter(pk=self.d.pk).exists())

    def test_site_scoped_operator(self):
        dr = Site.objects.create(tenant_key=T, name="DR Site", code="dr")
        u = User.objects.create_user("dr-op", password="pw")
        Membership.objects.create(user=u, site=dr, role="operator")
        self.login(u)
        r = self.c.get(reverse("network:all"))
        self.assertContains(r, "FG-01")
        self.assertNotContains(r, "core-sw-01")
        self.assertEqual(self.c.get(reverse("network:detail", args=[self.d.pk])).status_code, 404)
        self.assertEqual(self.c.get(reverse("network:edit", args=[self.fw.pk])).status_code, 200)
        data = {"name": "new-fw", "device_type": "firewall", "mgmt_ip": "192.0.2.1", "check_port": 22, "site": ""}
        r = self.c.post(reverse("network:create"), data)
        self.assertContains(r, "cannot manage devices on this site")
        with mock.patch("network.probe.tcp_probe", return_value=ok()):
            r = self.c.post(reverse("network:create"), dict(data, site="DR Site"))
        self.assertEqual(r.status_code, 302)
        self.assertTrue(Device.objects.filter(name="new-fw", site="DR Site").exists())


@override_settings(LINKEDEYE_TENANT=T, PROBE_ALLOWED_PRIVATE_CIDRS=["192.0.2.0/24"])
class DiscoveryViewTests(TestCase):
    def setUp(self):
        self.viewer, self.operator, self.admin = users()
        self.c = Client()
        self.c.force_login(self.operator)

    def test_start_validates_and_launches(self):
        r = self.c.post(reverse("network:discovery"), {"cidr": "192.0.2.0/16", "ports": "22"})
        self.assertContains(r, "too large")
        r = self.c.post(reverse("network:discovery"), {"cidr": "10.9.0.0/24", "ports": "22"})
        self.assertContains(r, "PROBE_ALLOWED_PRIVATE_CIDRS")
        with mock.patch("network.discovery.launch") as launch:
            r = self.c.post(reverse("network:discovery"), {"cidr": "192.0.2.7/29", "ports": "22, 443", "site": ""})
        run = DiscoveryRun.objects.get()
        self.assertRedirects(r, run.get_absolute_url())
        self.assertEqual((run.cidr, run.ports, run.status, run.requested_by), ("192.0.2.0/29", "22,443", "queued", self.operator))
        launch.assert_called_once_with(run)
        self.assertTrue(AuditEvent.objects.filter(action="discover", object_id=str(run.pk)).exists())
        self.assertEqual(self.c.get(run.get_absolute_url()).status_code, 200)
        self.assertEqual(self.c.get(reverse("network:discovery") + "?cidr=192.0.2.0/24").status_code, 200)

    def test_approve_ignore_cancel(self):
        run = DiscoveryRun.objects.create(tenant_key=T, cidr="192.0.2.0/29", ports="22,443", status="done", site="")
        h1 = DiscoveredHost.objects.create(run=run, ip="192.0.2.1", open_ports=[443, 22])
        h2 = DiscoveredHost.objects.create(run=run, ip="192.0.2.2", open_ports=[443])
        h3 = DiscoveredHost.objects.create(run=run, ip="192.0.2.3", open_ports=[80])
        dev("sw-192.0.2.2", mgmt_ip="192.0.2.99")  # name clash gets a suffix
        r = self.c.get(run.get_absolute_url())
        self.assertContains(r, "Approve selected")
        r = self.c.post(reverse("network:discovery_approve", args=[run.pk]),
                        {"host": [h1.pk, h2.pk], "device_type": "switch", "site": "", "name_prefix": "sw-"})
        self.assertRedirects(r, run.get_absolute_url())
        d1 = Device.objects.get(mgmt_ip="192.0.2.1")
        self.assertEqual((d1.name, d1.check_port, d1.device_type, d1.tags), ("sw-192.0.2.1", 22, "switch", "discovered"))
        d2 = Device.objects.get(mgmt_ip="192.0.2.2")
        self.assertEqual((d2.name, d2.check_port), ("sw-192.0.2.2-2", 443))
        h1.refresh_from_db()
        self.assertEqual((h1.status, h1.device, h1.decided_by_name), ("approved", d1, "operator"))
        self.assertEqual(AuditEvent.objects.filter(action="create", object_type="network.device").count(), 2)
        self.assertTrue(AuditEvent.objects.filter(action="approve", object_id=str(run.pk)).exists())
        # approving again does nothing (only "new" hosts can be approved)
        self.c.post(reverse("network:discovery_approve", args=[run.pk]), {"host": [h1.pk], "device_type": "switch"})
        self.assertEqual(Device.objects.filter(mgmt_ip="192.0.2.1").count(), 1)
        self.c.post(reverse("network:discovery_ignore", args=[run.pk]), {"host": [h3.pk]})
        h3.refresh_from_db()
        self.assertEqual(h3.status, "ignored")
        self.assertTrue(AuditEvent.objects.filter(action="ignore").exists())
        # configuration tab links back to the run
        r = self.c.get(reverse("network:detail", args=[d1.pk]) + "?tab=configuration")
        self.assertContains(r, run.get_absolute_url())

        active = DiscoveryRun.objects.create(tenant_key=T, cidr="192.0.2.0/30", status="running", started_at=timezone.now())
        self.c.post(reverse("network:discovery_cancel", args=[active.pk]))
        active.refresh_from_db()
        self.assertEqual(active.status, "cancelled")
        self.assertTrue(AuditEvent.objects.filter(action="cancel").exists())

    def test_viewer_cannot_approve(self):
        run = DiscoveryRun.objects.create(tenant_key=T, cidr="192.0.2.0/29", status="done")
        h = DiscoveredHost.objects.create(run=run, ip="192.0.2.1", open_ports=[22])
        c = Client()
        c.force_login(self.viewer)
        r = c.get(run.get_absolute_url())
        self.assertNotContains(r, "Approve selected")
        c.post(reverse("network:discovery_approve", args=[run.pk]), {"host": [h.pk], "device_type": "switch"})
        self.assertFalse(Device.objects.exists())


# ---------------------------------------------------------------------------------------------- seed
@override_settings(LINKEDEYE_TENANT=T)
class SeedTests(TestCase):
    def test_seed_is_idempotent_and_marked(self):
        call_command("seed_network", stdout=StringIO())
        call_command("seed_network", stdout=StringIO())
        qs = Device.objects.filter(tenant_key=T)
        self.assertEqual(qs.count(), 10)
        fg = qs.get(name="FG-01")
        self.assertEqual((fg.vendor, fg.model, fg.device_type), ("Fortinet", "FortiGate 100F", "firewall"))
        import ipaddress
        doc = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
        for d in qs:
            self.assertTrue(d.is_example, d.name)
            self.assertIn("Example record", d.description)
            self.assertTrue(any(ipaddress.ip_address(d.mgmt_ip) in n for n in doc), d.mgmt_ip)
        self.assertEqual(set(qs.values_list("device_type", flat=True)),
                         {"switch", "router", "firewall", "load_balancer", "wireless", "physical_server", "virtual_machine"})
        self.assertFalse(DevicePoll.objects.exists())  # no invented history
        self.assertFalse(Interface.objects.exists())

    def test_seed_keeps_real_devices_and_removes_examples(self):
        dev("FG-01", tags="prod")
        call_command("seed_network", stdout=StringIO())
        self.assertEqual(Device.objects.get(name="FG-01").tags, "prod")
        call_command("seed_network", "--remove", stdout=StringIO())
        self.assertEqual(list(Device.objects.values_list("name", flat=True)), ["FG-01"])
