"""Create clearly-marked example exporters and log lines for demos.

Example exporters have no metrics URL, so they honestly show as "Not Configured" until a real
endpoint is set. Example log lines carry attributes {"example": true}. Idempotent: existing
example exporters are left alone, and example log lines are only added when none exist
(use --refresh-logs to replace them with lines relative to now). Never runs automatically."""
import random
from datetime import timedelta

from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone

from observe.models import Exporter, ExporterStatus, LogEntry

NOTE = "Example exporter created by seed_observe – set a metrics URL to monitor a real endpoint."

EXPORTERS = [
    # name, type, category, target, site
    ("example-snmp-switch-01", "SNMP", "Network", "10.10.1.10", "Mumbai DC"),
    ("example-netflow-edge", "NetFlow", "Network", "192.168.10.1", "Mumbai DC"),
    ("example-fortigate-fw-01", "HTTP API", "Firewalls", "192.168.1.1", "Mumbai DC"),
    ("example-node-exporter-01", "Node Exporter", "Servers", "srv-app-01", "Mumbai DC"),
    ("example-windows-exporter", "Windows", "Servers", "win-srv-01", "Pune DR"),
    ("example-vmware-exporter", "vSphere", "Virtualization", "vcenter01", "Mumbai DC"),
    ("example-ceph-exporter", "Ceph", "Storage", "ceph-mon-01", "Pune DR"),
    ("example-mysql-exporter", "MySQL", "Databases", "db-prod-01", "Mumbai DC"),
    ("example-blackbox-exporter", "Blackbox (HTTP/TCP)", "Applications", "https://www.example.com", "All Sites"),
    ("example-kube-state-metrics", "Kubernetes", "Kubernetes", "k8s-cluster-01", "Bengaluru HQ"),
    ("example-unifi-exporter", "UniFi API", "Wireless", "unifi-ctrl-01", "Bengaluru HQ"),
    ("example-syslog-relay", "Syslog", "Security", "syslog-server", "Mumbai DC"),
    ("example-script-exporter", "Script", "Custom", "job-runner-01", "Pune DR"),
]

LINES = {
    "example-snmp-switch-01": [("INFO", "Interface Gi1/0/{n} status up"), ("WARN", "Interface Gi1/0/{n} CRC errors rising: {n}")],
    "example-fortigate-fw-01": [("WARN", "High session count: {k}"), ("INFO", "Policy {n} hit count updated")],
    "example-node-exporter-01": [("INFO", "CPU usage: {p}%"), ("WARN", "Filesystem /var at {p}%"), ("ERROR", "Disk read errors on sdb")],
    "example-windows-exporter": [("INFO", "Memory usage: {p}%"), ("INFO", "Service W32Time running")],
    "example-vmware-exporter": [("INFO", "Datastore usage: {p}%"), ("WARN", "VM snapshot older than 7 days: vm-{n}")],
    "example-mysql-exporter": [("INFO", "Queries per second: {k}"), ("ERROR", "Slow query detected ({s}s)")],
    "example-blackbox-exporter": [("INFO", "HTTPS check success (200)"), ("WARN", "HTTPS check slow: {k} ms")],
    "example-kube-state-metrics": [("INFO", "Pod restart detected: api-{h}"), ("CRITICAL", "Node k8s-node-0{n} NotReady")],
    "example-syslog-relay": [("WARN", "Failed login attempt from 10.1.1.{n}"), ("INFO", "Forwarded {k} messages")],
    "example-netflow-edge": [("INFO", "High traffic from 192.168.20.{n}")],
}


class Command(BaseCommand):
    help = "Create example exporters (no metrics URL) and example log lines, all marked as examples."

    def add_arguments(self, parser):
        parser.add_argument("--no-logs", action="store_true", help="Only create the example exporters.")
        parser.add_argument("--refresh-logs", action="store_true",
                            help="Delete the previous example log lines and create new ones relative to now.")
        parser.add_argument("--lines", type=int, default=400, help="Number of example log lines (default 400, max 5000).")

    def handle(self, *args, **opts):
        tenant = settings.LINKEDEYE_TENANT
        created = 0
        for name, typ, cat, target, site in EXPORTERS:
            _obj, new = Exporter.objects.get_or_create(
                tenant_key=tenant, name=name,
                defaults={"exporter_type": typ, "category": cat, "target": target, "site": site, "enabled": True,
                          "metrics_url": "", "description": NOTE, "status": ExporterStatus.NOT_CONFIGURED,
                          "status_changed_at": timezone.now(), "last_error": "No metrics URL configured"})
            created += new
        self.stdout.write(f"Example exporters: {created} created, {len(EXPORTERS) - created} already present.")
        if opts["no_logs"]:
            return
        examples = LogEntry.objects.filter(tenant_key=tenant, attributes__example=True)
        if examples.exists() and not opts["refresh_logs"]:
            self.stdout.write("Example log lines already present (use --refresh-logs to recreate them).")
            return
        removed = examples.delete()[0] if opts["refresh_logs"] else 0
        n = max(1, min(5000, opts["lines"]))
        rng = random.Random(42)
        now = timezone.now()
        sites = {e[0]: e[4] for e in EXPORTERS}
        targets = {e[0]: e[3] for e in EXPORTERS}
        sources = list(LINES)
        weights = [6, 3, 8, 4, 3, 5, 4, 3, 7, 2]
        rows = []
        for _ in range(n):
            src = rng.choices(sources, weights)[0]
            level, tmpl = rng.choice(LINES[src])
            msg = tmpl.format(n=rng.randint(1, 48), k=rng.randint(800, 9900), p=rng.randint(20, 97),
                              s=round(rng.uniform(1.1, 4.9), 1), h=f"{rng.randint(0, 0xfffff):05x}")
            ts = now - timedelta(seconds=rng.randint(0, 24 * 3600))
            rows.append(LogEntry(tenant_key=tenant, ts=ts, received_at=now, source=src, level=level,
                                 message=f"[example] {msg}", host=targets[src], site=sites[src],
                                 attributes={"example": True, "seeded_by": "seed_observe"}))
        LogEntry.objects.bulk_create(rows, batch_size=500)
        self.stdout.write(f"Example log lines: {len(rows)} created" + (f", {removed} old ones removed." if removed else "."))
