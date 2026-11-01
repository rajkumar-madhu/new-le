from django.conf import settings
from django.core.management.base import BaseCommand

from domainmonitor.models import Domain
from urlchecker.models import UrlCheck

URLS = [
    ("NSE Web Portal", "https://www.nseindia.com/", "web", "Mumbai (NSE)", "trading,exchange"),
    ("BSE Portal", "https://www.bseindia.com/", "web", "Mumbai (BSE)", "trading,exchange"),
    ("MCX Portal", "https://www.mcxindia.com/", "web", "Mumbai (MCX)", "trading,exchange"),
    ("WeCrew Website", "https://wecrew.in/", "web", "All Sites", "corporate"),
    ("Finspot Website", "https://finspot.in/", "web", "All Sites", "corporate"),
    ("GitHub API", "https://api.github.com/", "api", "All Sites", "external,api"),
    ("Example (IANA)", "https://example.com/", "web", "DR Site", "reference"),
]
DOMAINS = [
    ("wecrew.in", "Production", "All Sites", "Corporate", "WeCrew corporate website"),
    ("finspot.in", "Production", "All Sites", "Corporate", "Finspot corporate website"),
    ("nseindia.com", "Production", "Mumbai (NSE)", "Trading", "NSE public website"),
    ("bseindia.com", "Production", "Mumbai (BSE)", "Trading", "BSE public website"),
    ("mcxindia.com", "Production", "Mumbai (MCX)", "Trading", "MCX public website"),
    ("api.github.com", "API", "All Sites", "External", "Third-party API dependency"),
    ("example.com", "Test", "DR Site", "Reference", "IANA reference domain"),
    ("expired.badssl.com", "Test", "DR Site", "Reference", "Public test host with an expired certificate"),
    ("self-signed.badssl.com", "Test", "DR Site", "Reference", "Public test host with an untrusted certificate"),
]


class Command(BaseCommand):
    help = "Create example URL checks and domains (marked 'example' so they are easy to find and delete)."

    def handle(self, *args, **opts):
        t = settings.LINKEDEYE_TENANT
        n = 0
        for name, url, typ, site, tags in URLS:
            _, created = UrlCheck.objects.get_or_create(tenant_key=t, name=name, defaults={
                "url": url, "check_type": typ, "site": site, "tags": f"example,{tags}", "interval_seconds": 120})
            n += created
        for host, typ, site, group, desc in DOMAINS:
            _, created = Domain.objects.get_or_create(tenant_key=t, hostname=host, defaults={
                "domain_type": typ, "site_key": site, "group": group, "description": f"Example: {desc}"})
            n += created
        self.stdout.write(self.style.SUCCESS(f"Created {n} example record(s). Run `manage.py run_probes --once` to check them."))
