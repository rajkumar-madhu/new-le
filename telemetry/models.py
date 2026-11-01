"""Telemetry records.

* Alert       – one row per Alertmanager alert fingerprint, upserted by the webhook receiver
                (POST /api/v1/alertmanager/). Prometheus / Nagios data is read live and never stored.
* SavedQuery  – PromQL expressions saved from the Metrics Explorer.
"""
from django.conf import settings
from django.db import models
from django.utils import timezone


def _tenant():
    return settings.LINKEDEYE_TENANT


class AlertQuerySet(models.QuerySet):
    def for_tenant(self):
        return self.filter(tenant_key=settings.LINKEDEYE_TENANT)

    def firing(self):
        return self.filter(status=Alert.FIRING)

    def resolved(self):
        return self.filter(status=Alert.RESOLVED)


class Alert(models.Model):
    FIRING, RESOLVED = "firing", "resolved"
    STATUSES = [(FIRING, "Firing"), (RESOLVED, "Resolved")]

    tenant_key = models.CharField(max_length=100, db_index=True, default=_tenant)
    fingerprint = models.CharField(max_length=64, unique=True)
    status = models.CharField(max_length=10, choices=STATUSES, default=FIRING, db_index=True)
    alertname = models.CharField(max_length=200, db_index=True)
    severity = models.CharField(max_length=40, blank=True, db_index=True)
    instance = models.CharField(max_length=255, blank=True, db_index=True)
    job = models.CharField(max_length=200, blank=True)
    site = models.CharField(max_length=100, blank=True, db_index=True)
    summary = models.CharField(max_length=500, blank=True)
    description = models.TextField(blank=True)
    labels = models.JSONField(default=dict, blank=True)
    annotations = models.JSONField(default=dict, blank=True)
    receiver = models.CharField(max_length=200, blank=True)
    generator_url = models.CharField(max_length=1000, blank=True)
    starts_at = models.DateTimeField(null=True, blank=True)
    ends_at = models.DateTimeField(null=True, blank=True)
    last_received_at = models.DateTimeField(default=timezone.now, db_index=True)
    receive_count = models.PositiveIntegerField(default=1)
    fire_count = models.PositiveIntegerField(default=0)
    acknowledged_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
                                        related_name="+")
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = AlertQuerySet.as_manager()

    class Meta:
        ordering = ["-last_received_at"]
        indexes = [models.Index(fields=["tenant_key", "status", "severity"])]

    def __str__(self):
        return f"{self.alertname} ({self.instance})" if self.instance else self.alertname

    @property
    def event_fingerprint(self):
        return f"am:{self.fingerprint}"

    @property
    def is_example(self):
        return str((self.labels or {}).get("example", "")).lower() == "true"

    @property
    def acknowledged(self):
        return self.acknowledged_at is not None

    @property
    def severity_tone(self):
        return severity_tone(self.severity)

    @property
    def extra_labels(self):
        """Labels worth showing as chips (the well-known ones already have columns)."""
        skip = {"alertname", "severity", "instance", "job", "site"}
        return sorted((k, v) for k, v in (self.labels or {}).items() if k not in skip)

    @property
    def duration_seconds(self):
        if not self.starts_at:
            return None
        end = self.ends_at if self.status == self.RESOLVED and self.ends_at else timezone.now()
        return max(0, int((end - self.starts_at).total_seconds()))


def severity_tone(severity):
    s = (severity or "").lower()
    if s in ("critical", "page", "p1", "emergency", "error", "high"):
        return "crit"
    if s in ("warning", "warn", "medium", "p2", "p3"):
        return "warn"
    if s in ("info", "informational", "low", "p4", "none"):
        return "info"
    return "mute"


class SavedQuery(models.Model):
    tenant_key = models.CharField(max_length=100, db_index=True, default=_tenant)
    name = models.CharField(max_length=120)
    promql = models.TextField()
    range_key = models.CharField(max_length=8, default="1h")
    description = models.CharField(max_length=300, blank=True)
    shared = models.BooleanField(default=False, help_text="Visible to every user, not only the owner.")
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, null=True, blank=True,
                              related_name="telemetry_saved_queries")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]
        constraints = [models.UniqueConstraint(fields=["tenant_key", "owner", "name"], name="telemetry_savedquery_owner_name")]

    def __str__(self):
        return self.name
