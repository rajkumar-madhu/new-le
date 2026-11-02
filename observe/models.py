"""Exporter inventory and the central log store.

* Exporter – a Prometheus-style exporter (node_exporter, snmp_exporter, blackbox…) whose
  /metrics endpoint LinkedEye scrapes every minute to know whether it is alive.
* LogEntry – one log line received through the ingest API (POST /api/v1/logs/).
"""
from django.conf import settings
from django.db import models
from django.urls import reverse
from django.utils import timezone


class Category(models.TextChoices):
    NETWORK = "Network", "Network"
    FIREWALLS = "Firewalls", "Firewalls"
    SERVERS = "Servers", "Servers"
    VIRTUALIZATION = "Virtualization", "Virtualization"
    STORAGE = "Storage", "Storage"
    DATABASES = "Databases", "Databases"
    APPLICATIONS = "Applications", "Applications"
    KUBERNETES = "Kubernetes", "Kubernetes"
    WIRELESS = "Wireless", "Wireless"
    SECURITY = "Security", "Security"
    CUSTOM = "Custom", "Custom"


# category -> (icon, colour) for the category strip and the table's Category column
CATEGORY_STYLE = {
    "Network": ("network", "#2b4cff"), "Firewalls": ("brick", "#d92d20"), "Servers": ("server", "#7a4fd6"),
    "Virtualization": ("layers", "#a3479a"), "Storage": ("hdd", "#c27400"), "Databases": ("database", "#2338c9"),
    "Applications": ("app", "#cc4216"), "Kubernetes": ("hexagon", "#0e8a7a"), "Wireless": ("wifi", "#0f7a55"),
    "Security": ("shield", "#3d3a35"), "Custom": ("settings", "#6f6a61"),
}

# exporter types offered as suggestions in the form (free text is allowed)
EXPORTER_TYPES = [
    "Node Exporter", "Windows", "SNMP", "Blackbox (HTTP/TCP)", "HTTP API", "NetFlow", "Syslog", "vSphere", "Proxmox",
    "IPMI", "MySQL", "PostgreSQL", "Redis", "MongoDB", "Kubernetes", "cAdvisor", "Nginx", "JMX", "Ceph", "ONTAP API",
    "UniFi API", "Wazuh API", "Pushgateway", "Script", "Custom",
]


class ExporterStatus(models.TextChoices):
    ACTIVE = "active", "Active"
    ERROR = "error", "Error"
    INACTIVE = "inactive", "Inactive"
    NOT_CONFIGURED = "not_configured", "Not Configured"


class Exporter(models.Model):
    tenant_key = models.CharField(max_length=100, db_index=True, default=settings.LINKEDEYE_TENANT)
    name = models.CharField(max_length=120)
    exporter_type = models.CharField("Type", max_length=60)
    category = models.CharField(max_length=20, choices=Category.choices, default=Category.CUSTOM, db_index=True)
    target = models.CharField("Target / device", max_length=255, blank=True,
                              help_text="The device, host or service this exporter reports on.")
    metrics_url = models.URLField("Metrics URL", max_length=500, blank=True,
                                  help_text="Scraped every minute, e.g. http://10.10.1.20:9100/metrics. "
                                            "Leave empty when the exporter is not reachable from LinkedEye yet.")
    site = models.CharField(max_length=100, blank=True, db_index=True)
    enabled = models.BooleanField(default=True)
    description = models.TextField(blank=True)

    status = models.CharField(max_length=20, choices=ExporterStatus.choices, default=ExporterStatus.NOT_CONFIGURED,
                              db_index=True)
    status_changed_at = models.DateTimeField(null=True, blank=True)
    last_checked_at = models.DateTimeField(null=True, blank=True)
    last_seen = models.DateTimeField(null=True, blank=True, help_text="Last successful scrape.")
    last_scrape_ms = models.FloatField(null=True, blank=True)
    samples = models.PositiveIntegerField(null=True, blank=True, help_text="Metric samples in the last successful scrape.")
    last_error = models.CharField(max_length=500, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]
        constraints = [models.UniqueConstraint(fields=["tenant_key", "name"], name="observe_exporter_tenant_name_unique")]
        indexes = [models.Index(fields=["tenant_key", "status"]), models.Index(fields=["tenant_key", "category"])]

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("observe:exporter_detail", args=[self.pk])

    @property
    def cat_icon(self):
        return CATEGORY_STYLE.get(self.category, CATEGORY_STYLE["Custom"])[0]

    @property
    def cat_color(self):
        return CATEGORY_STYLE.get(self.category, CATEGORY_STYLE["Custom"])[1]

    @property
    def scrapeable(self):
        return self.enabled and bool(self.metrics_url)

    def config_status(self):
        """Status implied by the configuration alone (before any scrape result is known)."""
        if not self.enabled:
            return ExporterStatus.INACTIVE
        if not self.metrics_url:
            return ExporterStatus.NOT_CONFIGURED
        return None

    def set_status(self, status, now=None):
        if status != self.status:
            self.status = status
            self.status_changed_at = now or timezone.now()

    def apply_config_status(self, url_changed=False):
        """Bring `status` in line with enabled/metrics_url after an edit. Returns True when a scrape is needed."""
        implied = self.config_status()
        if implied is not None:
            self.set_status(implied)
            if implied == ExporterStatus.INACTIVE:
                self.last_error = ""
            else:
                self.last_error = "No metrics URL configured"
            return False
        if url_changed or self.status in (ExporterStatus.INACTIVE, ExporterStatus.NOT_CONFIGURED):
            # a new endpoint: the previous scrape figures belong to another URL
            self.set_status(ExporterStatus.NOT_CONFIGURED)
            self.last_error = "Waiting for the first scrape"
            self.samples = self.last_scrape_ms = None
            if url_changed:
                self.last_seen = None
        return True


class LogLevel(models.TextChoices):
    DEBUG = "DEBUG", "Debug"
    INFO = "INFO", "Info"
    WARN = "WARN", "Warn"
    ERROR = "ERROR", "Error"
    CRITICAL = "CRITICAL", "Critical"


LEVEL_ALIASES = {
    "TRACE": "DEBUG", "DEBUG": "DEBUG", "INFO": "INFO", "INFORMATION": "INFO", "NOTICE": "INFO", "WARN": "WARN",
    "WARNING": "WARN", "ERR": "ERROR", "ERROR": "ERROR", "CRIT": "CRITICAL", "CRITICAL": "CRITICAL",
    "FATAL": "CRITICAL", "ALERT": "CRITICAL", "EMERG": "CRITICAL", "EMERGENCY": "CRITICAL",
}


class LogEntry(models.Model):
    tenant_key = models.CharField(max_length=100, default=settings.LINKEDEYE_TENANT)
    ts = models.DateTimeField(default=timezone.now, db_index=True)
    source = models.CharField(max_length=120)
    level = models.CharField(max_length=10, choices=LogLevel.choices, default=LogLevel.INFO)
    message = models.TextField()
    host = models.CharField(max_length=255, blank=True)
    site = models.CharField(max_length=100, blank=True)
    attributes = models.JSONField(default=dict, blank=True)
    received_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["-ts", "-id"]
        verbose_name_plural = "log entries"
        indexes = [
            models.Index(fields=["tenant_key", "ts"], name="observe_log_tenant_ts"),
            models.Index(fields=["tenant_key", "source", "ts"], name="observe_log_source_ts"),
            models.Index(fields=["tenant_key", "level", "ts"], name="observe_log_level_ts"),
            models.Index(fields=["tenant_key", "site", "ts"], name="observe_log_site_ts"),
        ]

    def __str__(self):
        return f"{self.ts:%Y-%m-%d %H:%M:%S} {self.level} {self.source}: {self.message[:80]}"

    @property
    def tone(self):
        return {"DEBUG": "mute", "INFO": "info", "WARN": "warn", "ERROR": "crit", "CRITICAL": "crit"}.get(self.level, "mute")
