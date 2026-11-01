"""Create clearly-marked example TCP checks (tag "example"). Idempotent; never runs automatically.

The examples point at public services so they produce real results once the scheduler
(`manage.py run_probes`) runs, or immediately with --run. No results are fabricated.
"""
from django.conf import settings
from django.core.management.base import BaseCommand

from tcpcheck import services
from tcpcheck.models import SlaTarget, TcpCheck

EXAMPLES = [
    {"name": "Example – Cloudflare DNS (TCP 53)", "host": "1.1.1.1", "port": 53, "degraded_ms": 300,
     "description": "Example check: public DNS resolver over TCP."},
    {"name": "Example – Google DNS (TCP 53)", "host": "8.8.8.8", "port": 53, "degraded_ms": 300,
     "description": "Example check: public DNS resolver over TCP."},
    {"name": "Example – GitHub SSH", "host": "github.com", "port": 22, "expect_banner": "SSH-",
     "description": "Example check: SSH service that must answer with an SSH banner."},
    {"name": "Example – example.com HTTPS port", "host": "example.com", "port": 443,
     "description": "Example check: TCP connect to port 443."},
    {"name": "Example – Gmail SMTP submission", "host": "smtp.gmail.com", "port": 587, "expect_banner": "220",
     "description": "Example check: SMTP server that must greet with 220."},
]


class Command(BaseCommand):
    help = "Create example TCP checks tagged 'example' (idempotent). Use --run to check them once now."

    def add_arguments(self, parser):
        parser.add_argument("--run", action="store_true", help="Run the example checks once after creating them.")
        parser.add_argument("--remove", action="store_true", help="Delete the example checks (and their history).")

    def handle(self, *args, run=False, remove=False, **opts):
        tenant = settings.LINKEDEYE_TENANT
        if remove:
            qs = TcpCheck.objects.filter(tenant_key=tenant, name__in=[e["name"] for e in EXAMPLES])
            SlaTarget.objects.filter(tenant_key=tenant, kind="tcp", object_id__in=list(qs.values_list("pk", flat=True))).delete()
            n, _ = qs.delete()
            self.stdout.write(self.style.SUCCESS(f"Removed example TCP checks ({n} row(s) incl. history)."))
            return
        created = 0
        items = []
        for e in EXAMPLES:
            defaults = {"interval_seconds": 300, "timeout_seconds": 5, "degraded_ms": 500, "tags": "example",
                        "site": "All Sites", "expect_banner": "", **{k: v for k, v in e.items() if k != "name"}}
            obj, was_created = TcpCheck.objects.get_or_create(tenant_key=tenant, name=e["name"], defaults=defaults)
            created += was_created
            items.append(obj)
        self.stdout.write(self.style.SUCCESS(f"Example TCP checks: {created} created, {len(items) - created} already present."))
        if run:
            statuses = services.run_checks([c for c in items if c.enabled])
            for c, s in zip([c for c in items if c.enabled], statuses):
                self.stdout.write(f"  {c.name}: {s}")
