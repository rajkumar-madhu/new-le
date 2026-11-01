"""Network devices: inventory, reachability history, interfaces (from Prometheus
snmp_exporter) and subnet discovery runs."""
import ipaddress
import re

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.urls import reverse
from django.utils import timezone


def _tenant():
    return settings.LINKEDEYE_TENANT


HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$")


def validate_host(value):
    """An IPv4/IPv6 address or a DNS hostname."""
    value = (value or "").strip()
    try:
        ipaddress.ip_address(value)
        return
    except ValueError:
        pass
    if not HOSTNAME_RE.match(value) or value.replace(".", "").isdigit():
        raise ValidationError("Enter an IP address or a hostname.")


class DeviceType(models.TextChoices):
    SWITCH = "switch", "Switch"
    ROUTER = "router", "Router"
    FIREWALL = "firewall", "Firewall"
    LOAD_BALANCER = "load_balancer", "Load Balancer"
    WIRELESS = "wireless", "Wireless"
    PHYSICAL_SERVER = "physical_server", "Physical Server"
    VIRTUAL_MACHINE = "virtual_machine", "Virtual Machine"


# device_type -> (URL name of its list page, plural page title, icon)
TYPE_PAGES = {
    DeviceType.SWITCH: ("network:switches", "Switches", "network"),
    DeviceType.ROUTER: ("network:routers", "Routers", "share"),
    DeviceType.FIREWALL: ("network:firewalls", "Firewalls", "brick"),
    DeviceType.LOAD_BALANCER: ("network:load_balancers", "Load Balancers", "layers"),
    DeviceType.WIRELESS: ("network:wireless", "Wireless", "wifi"),
    DeviceType.PHYSICAL_SERVER: ("network:physical_servers", "Physical Servers", "server"),
    DeviceType.VIRTUAL_MACHINE: ("network:virtual_machines", "Virtual Machines", "cloud"),
}


class DeviceStatus(models.TextChoices):
    UP = "up", "Up"
    DOWN = "down", "Down"
    UNKNOWN = "unknown", "Unknown"


class Environment(models.TextChoices):
    # same keys as cmdb.Environment so devices and CIs line up
    PROD = "prod", "Production"
    UAT = "uat", "UAT"
    DR = "dr", "DR"
    DEV = "dev", "Development"


class Device(models.Model):
    tenant_key = models.CharField(max_length=100, db_index=True, default=_tenant)
    name = models.CharField(max_length=150)
    device_type = models.CharField("Type", max_length=20, choices=DeviceType.choices, default=DeviceType.SWITCH, db_index=True)
    vendor = models.CharField(max_length=100, blank=True)
    model = models.CharField(max_length=100, blank=True)
    serial = models.CharField("Serial number", max_length=100, blank=True)
    firmware = models.CharField("Firmware / OS version", max_length=150, blank=True)
    mgmt_ip = models.CharField("Management IP / host", max_length=255, validators=[validate_host],
                               help_text="Address the reachability check connects to.")
    check_port = models.PositiveIntegerField("Check port", default=22, validators=[MinValueValidator(1), MaxValueValidator(65535)],
                                             help_text="TCP port used for the reachability check (22 = SSH).")
    site = models.CharField(max_length=100, blank=True, default="", db_index=True)
    role = models.CharField(max_length=120, blank=True)
    environment = models.CharField(max_length=10, choices=Environment.choices, blank=True, default=Environment.PROD)
    contact = models.CharField(max_length=150, blank=True)
    description = models.TextField(blank=True)
    tags = models.CharField(max_length=300, blank=True, help_text="Comma-separated, e.g. core, dc1")
    prometheus_instance = models.CharField(
        "Prometheus instance", max_length=200, blank=True,
        help_text="The snmp_exporter target's instance label in Prometheus (often the device IP or name). "
                  "Leave empty when the device is not scraped.")
    enabled = models.BooleanField("Monitoring enabled", default=True)

    # reachability state (written by the poll job)
    status = models.CharField(max_length=10, choices=DeviceStatus.choices, default=DeviceStatus.UNKNOWN, db_index=True)
    last_seen = models.DateTimeField(null=True, blank=True)
    last_checked_at = models.DateTimeField(null=True, blank=True)
    last_latency_ms = models.FloatField(null=True, blank=True)
    last_error = models.CharField(max_length=300, blank=True)
    status_changed_at = models.DateTimeField(null=True, blank=True)
    consecutive_failures = models.PositiveIntegerField(default=0)

    # metrics state (written by the Prometheus job)
    uptime_seconds = models.BigIntegerField(null=True, blank=True)
    metrics_updated_at = models.DateTimeField(null=True, blank=True)
    metrics_error = models.CharField(max_length=300, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]
        constraints = [models.UniqueConstraint(fields=["tenant_key", "name"], name="network_device_tenant_name_unique")]
        indexes = [models.Index(fields=["tenant_key", "device_type", "status"])]

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("network:detail", args=[self.pk])

    @property
    def tag_list(self):
        return [t.strip() for t in self.tags.split(",") if t.strip()]

    @property
    def is_example(self):
        return "example" in [t.lower() for t in self.tag_list]

    @property
    def type_list_url(self):
        return reverse(TYPE_PAGES[self.device_type][0])

    @property
    def type_plural(self):
        return TYPE_PAGES[self.device_type][1]

    @property
    def type_icon(self):
        return TYPE_PAGES[self.device_type][2]

    @property
    def uptime_short(self):
        s = self.uptime_seconds
        if s is None:
            return ""
        days = int(s) // 86400
        if days:
            return f"{days} day{'s' if days != 1 else ''}"
        return f"{int(s) // 3600} h {int(s) % 3600 // 60} min"

    @property
    def uptime_display(self):
        s = self.uptime_seconds
        if s is None:
            return ""
        days, rem = divmod(int(s), 86400)
        hours, rem = divmod(rem, 3600)
        if days:
            return f"{days} day{'s' if days != 1 else ''}, {hours} hour{'s' if hours != 1 else ''}"
        return f"{hours} h {rem // 60} min"


class Interface(models.Model):
    """An interface as reported by snmp_exporter (IF-MIB) through Prometheus."""
    STATES = [("up", "Up"), ("down", "Down"), ("testing", "Testing"), ("unknown", "Unknown"), ("dormant", "Dormant"),
              ("notPresent", "Not present"), ("lowerLayerDown", "Lower layer down")]

    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name="interfaces")
    if_index = models.PositiveIntegerField()
    name = models.CharField(max_length=150)
    alias = models.CharField(max_length=200, blank=True)
    if_type = models.CharField(max_length=60, blank=True)
    admin_status = models.CharField(max_length=20, choices=STATES, default="unknown")
    oper_status = models.CharField(max_length=20, choices=STATES, default="unknown")
    speed_mbps = models.FloatField(null=True, blank=True)
    in_mbps = models.FloatField(null=True, blank=True)
    out_mbps = models.FloatField(null=True, blank=True)
    utilization = models.FloatField(null=True, blank=True, help_text="Busiest direction as % of interface speed")
    updated_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["device", "if_index"]
        constraints = [models.UniqueConstraint(fields=["device", "if_index"], name="network_interface_device_index_unique")]

    def __str__(self):
        return f"{self.device.name} {self.name}"

    @property
    def util_tone(self):
        u = self.utilization
        if u is None:
            return "mute"
        return "crit" if u >= 85 else "warn" if u >= 60 else "ok"


class DevicePoll(models.Model):
    """One reachability check (TCP connect to mgmt_ip:check_port)."""
    device = models.ForeignKey(Device, on_delete=models.CASCADE, related_name="polls")
    checked_at = models.DateTimeField(default=timezone.now, db_index=True)
    status = models.CharField(max_length=10, choices=DeviceStatus.choices)
    latency_ms = models.FloatField(null=True, blank=True)
    error = models.CharField(max_length=300, blank=True)

    class Meta:
        ordering = ["-checked_at"]
        indexes = [models.Index(fields=["device", "checked_at"])]

    def __str__(self):
        return f"{self.device_id} {self.status} @ {self.checked_at:%Y-%m-%d %H:%M}"


class DiscoveryRun(models.Model):
    STATUS = [("queued", "Queued"), ("running", "Running"), ("done", "Completed"), ("failed", "Failed"), ("cancelled", "Cancelled")]
    MAX_PORTS = 10

    tenant_key = models.CharField(max_length=100, db_index=True, default=_tenant)
    cidr = models.CharField("Network (CIDR)", max_length=64)
    ports = models.CharField(max_length=100, default="22,443")
    site = models.CharField(max_length=100, blank=True, default="", help_text="Site given to devices approved from this run")
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    requested_by_name = models.CharField(max_length=150, blank=True)
    status = models.CharField(max_length=10, choices=STATUS, default="queued", db_index=True)
    total_addresses = models.PositiveIntegerField(default=0)
    scanned = models.PositiveIntegerField(default=0)
    skipped = models.PositiveIntegerField(default=0, help_text="Addresses refused by the probe policy")
    found = models.PositiveIntegerField(default=0)
    error = models.CharField(max_length=300, blank=True)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"Discovery {self.cidr} ({self.get_status_display()})"

    def get_absolute_url(self):
        return reverse("network:discovery_run", args=[self.pk])

    @property
    def port_list(self):
        return [int(p) for p in self.ports.split(",") if p.strip().isdigit()]

    @property
    def active(self):
        return self.status in ("queued", "running")

    @property
    def progress(self):
        if not self.total_addresses:
            return 100 if self.status == "done" else 0
        return min(100, round(100 * (self.scanned + self.skipped) / self.total_addresses))

    @property
    def duration_s(self):
        if not self.started_at:
            return None
        return round(((self.finished_at or timezone.now()) - self.started_at).total_seconds())


class DiscoveredHost(models.Model):
    STATUS = [("new", "New"), ("approved", "Approved"), ("ignored", "Ignored"), ("existing", "Already a device")]

    run = models.ForeignKey(DiscoveryRun, on_delete=models.CASCADE, related_name="hosts")
    ip = models.GenericIPAddressField()
    open_ports = models.JSONField(default=list, blank=True)
    latency_ms = models.FloatField(null=True, blank=True)
    status = models.CharField(max_length=10, choices=STATUS, default="new", db_index=True)
    device = models.ForeignKey(Device, on_delete=models.SET_NULL, null=True, blank=True, related_name="discovered_as")
    decided_by_name = models.CharField(max_length=150, blank=True)
    decided_at = models.DateTimeField(null=True, blank=True)
    found_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["run", "id"]
        constraints = [models.UniqueConstraint(fields=["run", "ip"], name="network_discoveredhost_run_ip_unique")]

    def __str__(self):
        return f"{self.ip} ({self.get_status_display()})"

    @property
    def ports_display(self):
        return ", ".join(str(p) for p in self.open_ports)
