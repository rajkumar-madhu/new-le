"""CMDB and IT asset models.

ConfigurationItem is the single inventory record for hardware, software services and business
domains. Relationship links two CIs; impact flows along "dependency" relationships (see
IMPACT_FORWARD / IMPACT_REVERSE). Software and License cover the software asset register.
"""
from datetime import timedelta

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.urls import reverse
from django.utils import timezone


def _tenant():
    return settings.LINKEDEYE_TENANT


class CIType(models.TextChoices):
    SERVER = "server", "Server"
    VIRTUAL_MACHINE = "virtual_machine", "Virtual Machine"
    NETWORK_DEVICE = "network_device", "Network Device"
    APPLICATION = "application", "Application"
    DATABASE = "database", "Database"
    MIDDLEWARE = "middleware", "Middleware"
    SERVICE = "service", "Service"
    BUSINESS_DOMAIN = "business_domain", "Business Domain"
    KUBERNETES_CLUSTER = "kubernetes_cluster", "Kubernetes Cluster"
    STORAGE = "storage", "Storage"
    OTHER = "other", "Other"


# Physical / virtual kit shown on the IT Assets page (with purchase, warranty and EOL fields).
HARDWARE_TYPES = [CIType.SERVER, CIType.VIRTUAL_MACHINE, CIType.NETWORK_DEVICE, CIType.STORAGE]
# CIs that appear as rows under a business domain on the heatmap.
SERVICE_TYPES = [CIType.SERVICE, CIType.APPLICATION, CIType.DATABASE, CIType.MIDDLEWARE]
# Types whose CIs carry host metrics (node_exporter).
HOST_TYPES = [CIType.SERVER, CIType.VIRTUAL_MACHINE, CIType.KUBERNETES_CLUSTER, CIType.STORAGE, CIType.NETWORK_DEVICE]

TYPE_ICONS = {
    "server": "server", "virtual_machine": "cloud", "network_device": "network", "application": "app",
    "database": "database", "middleware": "layers", "service": "hexagon", "business_domain": "grid",
    "kubernetes_cluster": "hexagon", "storage": "hdd", "other": "box",
}


class CIStatus(models.TextChoices):
    PLANNED = "planned", "Planned"
    ACTIVE = "active", "Active"
    MAINTENANCE = "maintenance", "Maintenance"
    RETIRED = "retired", "Retired"


class Environment(models.TextChoices):
    PROD = "prod", "Production"
    UAT = "uat", "UAT"
    DR = "dr", "DR"
    DEV = "dev", "Development"


class ConfigurationItem(models.Model):
    tenant_key = models.CharField(max_length=100, db_index=True, default=_tenant)
    name = models.CharField(max_length=150)
    ci_type = models.CharField("Type", max_length=24, choices=CIType.choices, default=CIType.SERVER, db_index=True)
    status = models.CharField(max_length=12, choices=CIStatus.choices, default=CIStatus.ACTIVE, db_index=True)
    environment = models.CharField(max_length=8, choices=Environment.choices, default=Environment.PROD)
    site = models.CharField(max_length=100, default="All Sites", db_index=True)
    owner = models.CharField(max_length=120, blank=True)
    business_domain = models.CharField(max_length=120, blank=True, db_index=True,
                                       help_text="Business domain this CI belongs to (e.g. Trading).")
    description = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField("IP address", null=True, blank=True)
    vendor = models.CharField(max_length=120, blank=True)
    model = models.CharField(max_length=120, blank=True)
    serial = models.CharField("Serial number", max_length=120, blank=True)
    asset_tag = models.CharField(max_length=60, blank=True)
    purchase_date = models.DateField(null=True, blank=True)
    warranty_end = models.DateField(null=True, blank=True)
    eol_date = models.DateField("End of life", null=True, blank=True)
    cost = models.DecimalField(max_digits=14, decimal_places=2, null=True, blank=True,
                               validators=[MinValueValidator(0)])
    attributes = models.JSONField(default=dict, blank=True)
    url_checks = models.ManyToManyField("urlchecker.UrlCheck", blank=True, related_name="configuration_items")
    domains = models.ManyToManyField("domainmonitor.Domain", blank=True, related_name="configuration_items")
    prometheus_instance = models.CharField(max_length=200, blank=True,
                                           help_text="node_exporter instance label, e.g. prod-oms-01:9100")
    # last lifecycle alert state raised by the lifecycle job ("" = none); used to emit each transition once
    lifecycle_flag = models.CharField(max_length=40, blank=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]
        verbose_name = "configuration item"
        constraints = [models.UniqueConstraint(fields=["tenant_key", "name"], name="cmdb_ci_tenant_name_unique")]
        indexes = [models.Index(fields=["tenant_key", "ci_type"])]

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("cmdb:item_detail", args=[self.pk])

    @property
    def icon(self):
        return TYPE_ICONS.get(self.ci_type, "box")

    @property
    def is_hardware(self):
        return self.ci_type in HARDWARE_TYPES

    @property
    def is_example(self):
        return bool((self.attributes or {}).get("example"))

    def days_until(self, field):
        d = getattr(self, field)
        return None if d is None else (d - timezone.localdate()).days

    @property
    def warranty_days(self):
        return self.days_until("warranty_end")

    @property
    def eol_days(self):
        return self.days_until("eol_date")


class RelType(models.TextChoices):
    DEPENDS_ON = "depends_on", "Depends on"
    RUNS_ON = "runs_on", "Runs on"
    HOSTED_ON = "hosted_on", "Hosted on"
    CONNECTS_TO = "connects_to", "Connects to"
    PART_OF = "part_of", "Part of"


# Impact direction. "A depends_on B": B failing impacts A (reverse). "A part_of B": A failing impacts B (forward).
IMPACT_REVERSE = {RelType.DEPENDS_ON, RelType.RUNS_ON, RelType.HOSTED_ON}
IMPACT_FORWARD = {RelType.PART_OF}


class Relationship(models.Model):
    ORIGINS = [("manual", "Manual"), ("discovered", "Discovered")]

    source = models.ForeignKey(ConfigurationItem, on_delete=models.CASCADE, related_name="outgoing")
    target = models.ForeignKey(ConfigurationItem, on_delete=models.CASCADE, related_name="incoming")
    rel_type = models.CharField("Type", max_length=16, choices=RelType.choices, default=RelType.DEPENDS_ON)
    origin = models.CharField(max_length=12, choices=ORIGINS, default="manual")
    confidence = models.PositiveSmallIntegerField(default=100, validators=[MinValueValidator(0), MaxValueValidator(100)],
                                                  help_text="0-100; discovered links may be less certain.")
    note = models.CharField(max_length=300, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["source__name", "rel_type", "target__name"]
        constraints = [models.UniqueConstraint(fields=["source", "target", "rel_type"], name="cmdb_rel_unique_triple")]

    def __str__(self):
        return f"{self.source} {self.get_rel_type_display().lower()} {self.target}"

    def clean(self):
        if self.source_id and self.source_id == self.target_id:
            raise ValidationError("A CI cannot be related to itself.")
        if self.source_id and self.target_id and self.source.tenant_key != self.target.tenant_key:
            raise ValidationError("Both CIs must belong to the same tenant.")


class Software(models.Model):
    tenant_key = models.CharField(max_length=100, db_index=True, default=_tenant)
    name = models.CharField(max_length=150)
    vendor = models.CharField(max_length=120, blank=True)
    version = models.CharField(max_length=60, blank=True)
    category = models.CharField(max_length=60, blank=True, help_text="e.g. Operating System, Database, Monitoring")
    description = models.TextField(blank=True)
    installs = models.ManyToManyField(ConfigurationItem, blank=True, related_name="software")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name", "version"]
        verbose_name_plural = "software"
        constraints = [models.UniqueConstraint(fields=["tenant_key", "name", "version"], name="cmdb_sw_unique")]

    def __str__(self):
        return f"{self.name} {self.version}".strip()


class License(models.Model):
    tenant_key = models.CharField(max_length=100, db_index=True, default=_tenant)
    product = models.CharField(max_length=150)
    vendor = models.CharField(max_length=120, blank=True)
    software = models.ForeignKey(Software, on_delete=models.SET_NULL, null=True, blank=True, related_name="licenses",
                                 help_text="Usage is counted from this software's installs.")
    license_type = models.CharField(max_length=40, blank=True, help_text="e.g. Subscription, Perpetual, Per core")
    seats = models.PositiveIntegerField(default=1)
    expiry = models.DateField(null=True, blank=True)
    cost = models.DecimalField(max_digits=14, decimal_places=2, null=True, blank=True, validators=[MinValueValidator(0)])
    reference = models.CharField(max_length=120, blank=True, help_text="Contract / PO reference (never the license key).")
    notes = models.TextField(blank=True)
    alert_flag = models.CharField(max_length=40, blank=True, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["product"]

    def __str__(self):
        return self.product

    @property
    def used(self):
        if not self.software_id:
            return 0
        cached = getattr(self, "_used", None)
        if cached is None:
            cached = self.software.installs.count()
        return cached

    @property
    def over_allocated(self):
        return self.used > self.seats

    @property
    def usage_pct(self):
        return 100.0 * self.used / self.seats if self.seats else (100.0 if self.used else 0.0)

    @property
    def days_left(self):
        return None if self.expiry is None else (self.expiry - timezone.localdate()).days

    @property
    def expired(self):
        return self.days_left is not None and self.days_left < 0

    def expiring_within(self, days):
        d = self.days_left
        return d is not None and 0 <= d <= days

    @property
    def state(self):
        if self.expired:
            return "expired"
        if self.over_allocated:
            return "over"
        if self.expiring_within(60):
            return "expiring"
        return "ok"


def soon(days):
    return timezone.localdate() + timedelta(days=days)
