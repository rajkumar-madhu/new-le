from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils.text import slugify

from core.models import Site
from domainmonitor.models import Domain
from urlchecker.models import UrlCheck


class Command(BaseCommand):
    help = "Create Site records for every site name already used by URL checks and domains."

    def handle(self, *args, **opts):
        t = settings.LINKEDEYE_TENANT
        names = set(UrlCheck.objects.filter(tenant_key=t).values_list("site", flat=True)) | \
            set(Domain.objects.filter(tenant_key=t).values_list("site_key", flat=True))
        made = 0
        for name in sorted(n for n in names if n and n != "All Sites"):
            base = slugify(name)[:50] or "site"
            code, i = base, 2
            while Site.objects.filter(tenant_key=t, code=code).exclude(name=name).exists():
                code, i = f"{base}-{i}", i + 1
            _, created = Site.objects.get_or_create(tenant_key=t, name=name, defaults={"code": code})
            made += created
        self.stdout.write(self.style.SUCCESS(f"{made} site(s) created, {Site.objects.filter(tenant_key=t).count()} in total."))
