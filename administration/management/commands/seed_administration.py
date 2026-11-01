"""Create clearly-marked example sites and users for demos. Idempotent; never runs automatically.

Example users get an unusable password (they cannot sign in until an administrator sets one on the Users page)
and the e-mail domain example.com. Example sites carry "example" in their description."""
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.db import transaction

from core.models import Membership, Site

EXAMPLE_SITES = [
    {"name": "Example DC Mumbai", "code": "example-dc-mumbai", "region": "West India", "timezone": "Asia/Kolkata",
     "criticality": "critical", "description": "example – primary data centre (demo record)"},
    {"name": "Example DR Chennai", "code": "example-dr-chennai", "region": "South India", "timezone": "Asia/Kolkata",
     "criticality": "high", "description": "example – disaster-recovery site (demo record)"},
    {"name": "Example Branch London", "code": "example-branch-london", "region": "Europe", "timezone": "Europe/London",
     "criticality": "standard", "description": "example – branch office (demo record)"},
]

EXAMPLE_USERS = [
    {"username": "example.admin", "first_name": "Example", "last_name": "Admin", "memberships": [(None, "admin")]},
    {"username": "example.noc", "first_name": "Example", "last_name": "NOC Operator",
     "memberships": [("Example DC Mumbai", "operator"), ("Example DR Chennai", "operator")]},
    {"username": "example.viewer", "first_name": "Example", "last_name": "Viewer",
     "memberships": [("Example Branch London", "viewer")]},
]


class Command(BaseCommand):
    help = "Create example sites and users (marked 'example'; example users cannot sign in until given a password)."

    @transaction.atomic
    def handle(self, *args, **opts):
        User = get_user_model()
        tenant = settings.LINKEDEYE_TENANT
        sites_made = users_made = ms_made = 0
        sites = {}
        for spec in EXAMPLE_SITES:
            site = Site.objects.filter(tenant_key=tenant, name=spec["name"]).first()
            if site is None:
                code, i = spec["code"], 2
                while Site.objects.filter(tenant_key=tenant, code=code).exists():
                    code, i = f"{spec['code']}-{i}", i + 1
                site = Site.objects.create(tenant_key=tenant, **{**spec, "code": code})
                sites_made += 1
            sites[spec["name"]] = site
        for spec in EXAMPLE_USERS:
            user = User.objects.filter(username=spec["username"]).first()
            if user is None:
                user = User(username=spec["username"], first_name=spec["first_name"], last_name=spec["last_name"],
                            email=f"{spec['username']}@example.com")
                user.set_unusable_password()
                user.save()
                users_made += 1
            for site_name, role in spec["memberships"]:
                site = sites.get(site_name) if site_name else None
                qs = Membership.objects.filter(user=user, site=site) if site else Membership.objects.filter(user=user, site__isnull=True)
                if not qs.exists():
                    Membership.objects.create(user=user, site=site, role=role)
                    ms_made += 1
        self.stdout.write(self.style.SUCCESS(
            f"Example data: {sites_made} site(s), {users_made} user(s), {ms_made} membership(s) created."))
