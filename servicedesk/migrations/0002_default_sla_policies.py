"""Seed sensible default SLA targets per priority for the configured tenant (editable in the admin)."""
from django.conf import settings
from django.db import migrations

DEFAULTS = [
    # priority, name, response minutes, resolution minutes
    ("P1", "Critical", 15, 4 * 60),
    ("P2", "High", 30, 8 * 60),
    ("P3", "Medium", 4 * 60, 24 * 60),
    ("P4", "Low", 8 * 60, 72 * 60),
]


def seed(apps, schema_editor):
    SlaPolicy = apps.get_model("servicedesk", "SlaPolicy")
    tenant = settings.LINKEDEYE_TENANT
    for prio, name, resp, res in DEFAULTS:
        SlaPolicy.objects.get_or_create(tenant_key=tenant, priority=prio, defaults={
            "name": name, "response_minutes": resp, "resolution_minutes": res, "active": True})


def unseed(apps, schema_editor):
    SlaPolicy = apps.get_model("servicedesk", "SlaPolicy")
    SlaPolicy.objects.filter(tenant_key=settings.LINKEDEYE_TENANT, priority__in=[d[0] for d in DEFAULTS]).delete()


class Migration(migrations.Migration):
    dependencies = [("servicedesk", "0001_initial")]
    operations = [migrations.RunPython(seed, unseed)]
