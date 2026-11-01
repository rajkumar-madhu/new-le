"""Telnet / TCP reachability checks and the SLA targets used by the unified Uptime page."""
from decimal import Decimal

from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.urls import reverse
from django.utils import timezone

DEFAULT_SLA = Decimal("99.900")


class Status(models.TextChoices):
    ONLINE = "online", "Online"
    DEGRADED = "degraded", "Degraded"
    DOWN = "down", "Down"
    UNKNOWN = "unknown", "Unknown"


class TcpCheck(models.Model):
    INTERVALS = [(30, "30 seconds"), (60, "1 minute"), (120, "2 minutes"), (300, "5 minutes"), (600, "10 minutes"),
                 (900, "15 minutes")]

    tenant_key = models.CharField(max_length=100, db_index=True, default=settings.LINKEDEYE_TENANT)
    name = models.CharField(max_length=120)
    host = models.CharField(max_length=253, help_text="Hostname or IP address.")
    port = models.PositiveIntegerField(validators=[MinValueValidator(1), MaxValueValidator(65535)])
    site = models.CharField(max_length=100, default="All Sites", db_index=True)
    tags = models.CharField(max_length=200, blank=True)
    description = models.CharField(max_length=300, blank=True)
    interval_seconds = models.PositiveIntegerField(choices=INTERVALS, default=60)
    timeout_seconds = models.PositiveSmallIntegerField(default=5, validators=[MinValueValidator(1), MaxValueValidator(30)])
    degraded_ms = models.PositiveIntegerField(default=500, validators=[MinValueValidator(1), MaxValueValidator(60000)],
                                              help_text="Connections slower than this are Degraded.")
    expect_banner = models.CharField(max_length=200, blank=True,
                                     help_text="Optional text the server must send first (e.g. SSH-, 220).")
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # latest result, denormalised for list views and other modules
    last_status = models.CharField(max_length=10, choices=Status.choices, default=Status.UNKNOWN, db_index=True)
    last_checked_at = models.DateTimeField(null=True, blank=True)
    last_response_ms = models.FloatField(null=True, blank=True)
    last_error = models.CharField(max_length=500, blank=True)
    last_ip = models.GenericIPAddressField(null=True, blank=True)
    last_banner = models.CharField(max_length=200, blank=True)

    class Meta:
        ordering = ["name"]
        constraints = [models.UniqueConstraint(fields=["tenant_key", "name"], name="tcpcheck_tenant_name_unique")]

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("tcpcheck:detail", args=[self.pk])

    @property
    def target(self):
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"

    @property
    def tag_list(self):
        return [t.strip() for t in self.tags.split(",") if t.strip()]

    def is_due(self, now=None):
        now = now or timezone.now()
        return self.enabled and (self.last_checked_at is None
                                 or (now - self.last_checked_at).total_seconds() >= self.interval_seconds)


class TcpResult(models.Model):
    tcp_check = models.ForeignKey(TcpCheck, on_delete=models.CASCADE, related_name="results")
    checked_at = models.DateTimeField(db_index=True)
    status = models.CharField(max_length=10, choices=Status.choices)
    response_ms = models.FloatField(null=True, blank=True, help_text="TCP connect time.")
    ip = models.GenericIPAddressField(null=True, blank=True)
    banner = models.CharField(max_length=200, blank=True)
    message = models.CharField(max_length=500, blank=True)

    class Meta:
        ordering = ["-checked_at"]
        indexes = [models.Index(fields=["tcp_check", "checked_at"])]

    def __str__(self):
        return f"{self.tcp_check_id} {self.status} @ {self.checked_at:%Y-%m-%d %H:%M:%S}"


class SlaTarget(models.Model):
    """Availability target for one monitored target on the Uptime page (URL check, TCP check or domain).
    Targets without a row use DEFAULT_SLA."""
    KINDS = [("url", "URL"), ("tcp", "TCP"), ("domain", "Domain")]

    tenant_key = models.CharField(max_length=100, db_index=True, default=settings.LINKEDEYE_TENANT)
    kind = models.CharField(max_length=10, choices=KINDS)
    object_id = models.PositiveBigIntegerField()
    target = models.DecimalField(max_digits=6, decimal_places=3, default=DEFAULT_SLA,
                                 validators=[MinValueValidator(Decimal("50")), MaxValueValidator(Decimal("100"))])
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["tenant_key", "kind", "object_id"], name="tcpcheck_sla_unique")]

    def __str__(self):
        return f"{self.kind}:{self.object_id} {self.target}%"
