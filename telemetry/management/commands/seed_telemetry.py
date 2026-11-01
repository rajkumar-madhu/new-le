"""manage.py seed_telemetry – clearly-marked example Alertmanager alerts and saved PromQL queries.

Idempotent (re-running updates the same rows) and never run automatically. Example alerts carry the label
example="true" and an "(example)" summary; example queries are named "Example: …". No events are emitted, so
Service Desk does not open incidents for them. Remove them with --remove.
"""
from datetime import timedelta

from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone

from telemetry.models import Alert, SavedQuery

ALERTS = [
    # fingerprint, status, alertname, severity, instance, job, summary, description, started (min ago), ended (min ago)
    ("example00000001", "firing", "HostHighCpuLoad", "warning", "app-01.example:9100", "node",
     "CPU load above 85% for 10 minutes", "CPU busy on app-01 has been above 85% for more than 10 minutes.", 25, None),
    ("example00000002", "firing", "HostOutOfDiskSpace", "critical", "db-01.example:9100", "node",
     "Root filesystem has less than 10% free", "/ on db-01 is 92% full.", 70, None),
    ("example00000003", "firing", "TargetDown", "critical", "web-02.example:9100", "node",
     "Prometheus cannot scrape web-02", "up == 0 for 5 minutes.", 12, None),
    ("example00000004", "resolved", "HostMemoryPressure", "warning", "app-02.example:9100", "node",
     "Available memory below 10%", "MemAvailable on app-02 dropped below 10%.", 240, 180),
    ("example00000005", "resolved", "ProbeFailed", "page", "https://portal.example", "blackbox",
     "HTTP probe failing", "The blackbox exporter could not reach the portal.", 600, 560),
]

QUERIES = [
    ("Example: CPU busy % by host", '100 * (1 - avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])))', "6h"),
    ("Example: memory used %", "100 * (1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)", "6h"),
    ("Example: targets down", "up == 0", "1h"),
    ("Example: scrape duration by job", "avg by (job) (scrape_duration_seconds)", "24h"),
]


class Command(BaseCommand):
    help = "Create (or remove with --remove) example telemetry alerts and saved queries, marked 'example'."

    def add_arguments(self, parser):
        parser.add_argument("--remove", action="store_true", help="Delete the example rows instead.")

    def handle(self, *args, remove=False, **opts):
        tenant = settings.LINKEDEYE_TENANT
        if remove:
            n1, _ = Alert.objects.filter(fingerprint__startswith="example", labels__example="true").delete()
            n2, _ = SavedQuery.objects.filter(tenant_key=tenant, owner__isnull=True, name__startswith="Example: ").delete()
            self.stdout.write(self.style.SUCCESS(f"Removed {n1} example alert(s) and {n2} example query(ies)."))
            return
        now = timezone.now()
        created = 0
        for fp, status, name, sev, inst, job, summary, desc, start_min, end_min in ALERTS:
            labels = {"alertname": name, "severity": sev, "instance": inst, "job": job, "env": "example", "example": "true"}
            _obj, was_created = Alert.objects.update_or_create(fingerprint=fp, defaults={
                "tenant_key": tenant, "status": status, "alertname": name, "severity": sev, "instance": inst, "job": job,
                "summary": f"{summary} (example)", "description": f"{desc}\n\nExample alert created by manage.py seed_telemetry.",
                "labels": labels, "annotations": {"summary": f"{summary} (example)", "description": desc},
                "receiver": "linkedeye", "starts_at": now - timedelta(minutes=start_min),
                "ends_at": (now - timedelta(minutes=end_min)) if end_min is not None else None,
                "last_received_at": now - timedelta(minutes=end_min or 1), "fire_count": 1, "receive_count": 1,
            })
            created += was_created
        q_created = 0
        for name, promql, rng in QUERIES:
            _obj, was_created = SavedQuery.objects.update_or_create(
                tenant_key=tenant, owner=None, name=name,
                defaults={"promql": promql, "range_key": rng, "shared": True, "description": "Example query (seed_telemetry)"})
            q_created += was_created
        self.stdout.write(self.style.SUCCESS(
            f"Example telemetry data ready: {len(ALERTS)} alerts ({created} new), {len(QUERIES)} saved queries ({q_created} new)."))
