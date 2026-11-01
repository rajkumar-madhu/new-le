from django.conf import settings
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.utils import timezone


class Status(models.TextChoices):
    ONLINE = "online", "Online"
    DEGRADED = "degraded", "Degraded"
    DOWN = "down", "Down"
    UNKNOWN = "unknown", "Unknown"


class UrlCheck(models.Model):
    TYPES = [("web", "Web"), ("api", "API")]
    METHODS = [("GET", "GET"), ("HEAD", "HEAD")]
    INTERVALS = [(60, "1 minute"), (120, "2 minutes"), (300, "5 minutes"), (600, "10 minutes"), (900, "15 minutes")]

    tenant_key = models.CharField(max_length=100, db_index=True, default=settings.LINKEDEYE_TENANT)
    name = models.CharField(max_length=120)
    url = models.URLField(max_length=2000)
    check_type = models.CharField(max_length=10, choices=TYPES, default="web")
    method = models.CharField(max_length=6, choices=METHODS, default="GET")
    expected_status = models.PositiveSmallIntegerField(default=200, validators=[MinValueValidator(100), MaxValueValidator(599)])
    expected_text = models.CharField(max_length=200, blank=True, help_text="Optional text the response body must contain.")
    interval_seconds = models.PositiveIntegerField(choices=INTERVALS, default=300)
    timeout_seconds = models.PositiveSmallIntegerField(default=10, validators=[MinValueValidator(1), MaxValueValidator(60)])
    degraded_ms = models.PositiveIntegerField(default=1000, help_text="Responses slower than this are Degraded.")
    follow_redirects = models.BooleanField(default=True)
    site = models.CharField(max_length=100, default="All Sites")
    tags = models.CharField(max_length=200, blank=True)
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # latest result, denormalised for list views
    last_checked_at = models.DateTimeField(null=True, blank=True)
    last_status = models.CharField(max_length=10, choices=Status.choices, default=Status.UNKNOWN)
    last_http_status = models.PositiveSmallIntegerField(null=True, blank=True)
    last_response_ms = models.FloatField(null=True, blank=True)
    last_error = models.CharField(max_length=500, blank=True)

    class Meta:
        ordering = ["name"]
        constraints = [models.UniqueConstraint(fields=["tenant_key", "name"], name="urlcheck_tenant_name_unique")]

    def __str__(self):
        return self.name

    @property
    def tag_list(self):
        return [t.strip() for t in self.tags.split(",") if t.strip()]

    def is_due(self, now=None):
        now = now or timezone.now()
        return self.enabled and (self.last_checked_at is None or (now - self.last_checked_at).total_seconds() >= self.interval_seconds)


class UrlResult(models.Model):
    url_check = models.ForeignKey(UrlCheck, on_delete=models.CASCADE, related_name="results")
    checked_at = models.DateTimeField(db_index=True)
    status = models.CharField(max_length=10, choices=Status.choices)
    http_status = models.PositiveSmallIntegerField(null=True, blank=True)
    response_ms = models.FloatField(null=True, blank=True)
    tls_expires_at = models.DateTimeField(null=True, blank=True)
    message = models.CharField(max_length=500, blank=True)

    class Meta:
        ordering = ["-checked_at"]
        indexes = [models.Index(fields=["url_check", "checked_at"])]
