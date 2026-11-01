"""Create clearly-marked example domains for demos (`manage.py seed_domainmonitor`).

The examples are public hosts whose TLS / header set-up differs, so the Uptime, Performance and Security
pages show a spread of real results once they are checked. No check history, response time or scan
result is invented: pass `--check` to run real availability checks and security scans right away (needs
outbound HTTPS), otherwise `manage.py run_probes` picks them up. Idempotent; `--remove` deletes them.
"""
from django.conf import settings
from django.core.management.base import BaseCommand

from domainmonitor.models import Domain

PREFIX = "Example:"
GROUP = "Examples"

EXAMPLES = [
    # hostname, type, site, description
    ("example.com", "Test", "All Sites", "IANA reference domain (no security headers)"),
    ("github.com", "Production", "All Sites", "Public site with a strict security-header set"),
    ("badssl.com", "Test", "All Sites", "badssl.com landing page"),
    ("expired.badssl.com", "Test", "DR Site", "Public test host with an expired certificate"),
    ("self-signed.badssl.com", "Test", "DR Site", "Public test host with an untrusted certificate"),
    ("hsts.badssl.com", "Test", "DR Site", "Public test host that sends HSTS"),
]


class Command(BaseCommand):
    help = "Create (or remove with --remove) clearly-marked example domains; --check runs real checks and scans."

    def add_arguments(self, parser):
        parser.add_argument("--remove", action="store_true", help="Delete the example domains instead.")
        parser.add_argument("--check", action="store_true",
                            help="Run availability checks and security scans for the examples now (network).")

    def handle(self, *args, remove=False, check=False, **opts):
        tenant = settings.LINKEDEYE_TENANT
        hosts = [e[0] for e in EXAMPLES]
        examples = Domain.objects.filter(tenant_key=tenant, hostname__in=hosts, description__startswith=PREFIX)
        if remove:
            n = examples.count()
            examples.delete()
            self.stdout.write(self.style.SUCCESS(f"Removed {n} example domain(s)."))
            return
        created = 0
        for host, typ, site, desc in EXAMPLES:
            _, new = Domain.objects.get_or_create(tenant_key=tenant, hostname=host, defaults={
                "domain_type": typ, "site_key": site, "group": GROUP, "description": f"{PREFIX} {desc}"})
            created += new
        skipped = len(hosts) - examples.count()
        msg = f"Created {created} example domain(s)"
        if skipped:
            msg += f"; {skipped} host(s) already exist as real (non-example) domains and were left untouched"
        self.stdout.write(self.style.SUCCESS(msg + "."))
        if check:
            from domainmonitor import security
            from probes import runner
            items = list(examples.filter(is_active=True))
            runner.run_domain_checks(items)
            scans = security.run_scans(items)
            for s in scans:
                self.stdout.write(f"  {s.domain.hostname}: grade {s.grade or '–'}{' (' + s.error + ')' if s.error else ''}")
        else:
            self.stdout.write("Run `manage.py run_probes --once` (or pass --check) to check and scan them.")
