from django.core.validators import RegexValidator
from django.db import models
from django.utils import timezone

# The original patch used "\\." inside a raw string, which requires a literal
# backslash and rejected every real hostname (e.g. nse.finspot.in).
hostname_validator = RegexValidator(
    regex=r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$",
    message="Enter a fully qualified DNS hostname.",
)

DOMAIN_TYPES = ["Production", "Application", "API", "Monitoring", "Backup", "VPN", "Mail", "Test"]


class Domain(models.Model):
    tenant_key = models.CharField(max_length=100, db_index=True)
    site_key = models.CharField(max_length=100, db_index=True)
    hostname = models.CharField(max_length=253, validators=[hostname_validator])
    domain_type = models.CharField(max_length=32, default="Production")
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    dns_status = models.CharField(max_length=20, default="Unknown")   # Unknown | Resolved | Failed
    ssl_status = models.CharField(max_length=20, default="Unknown")   # Unknown | Valid | Expiring | Expired | Invalid | Unreachable
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    # monitoring (added in 0002)
    group = models.CharField(max_length=64, blank=True)
    monitor_enabled = models.BooleanField(default=True)
    check_interval_seconds = models.PositiveIntegerField(default=300)
    status = models.CharField(max_length=10, default="unknown")       # unknown | up | down
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    http_status = models.PositiveSmallIntegerField(null=True, blank=True)
    response_ms = models.FloatField(null=True, blank=True)
    ssl_expires_at = models.DateTimeField(null=True, blank=True)
    last_checked_at = models.DateTimeField(null=True, blank=True)
    last_error = models.CharField(max_length=500, blank=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["tenant_key", "hostname"], name="domain_tenant_hostname_unique")
        ]
        ordering = ["hostname"]

    def __str__(self):
        return self.hostname

    def is_due(self, now=None):
        now = now or timezone.now()
        return (self.is_active and self.monitor_enabled and
                (self.last_checked_at is None or (now - self.last_checked_at).total_seconds() >= self.check_interval_seconds))

    @property
    def ssl_days_left(self):
        if not self.ssl_expires_at:
            return None
        return (self.ssl_expires_at - timezone.now()).days


class DomainCheck(models.Model):
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, related_name="checks")
    checked_at = models.DateTimeField(db_index=True)
    up = models.BooleanField()
    http_status = models.PositiveSmallIntegerField(null=True, blank=True)
    response_ms = models.FloatField(null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    dns_status = models.CharField(max_length=20)
    ssl_status = models.CharField(max_length=20)
    ssl_expires_at = models.DateTimeField(null=True, blank=True)
    message = models.CharField(max_length=500, blank=True)

    class Meta:
        ordering = ["-checked_at"]
        indexes = [models.Index(fields=["domain", "checked_at"])]


GRADES = ["A", "B", "C", "D", "E", "F"]


class DomainSecurityScan(models.Model):
    """One HTTPS security scan of a domain: negotiated TLS parameters, certificate and response headers.

    `grade` is empty when the scan could not reach the site (see `error`); `findings` holds one entry per
    check: {"key", "label", "passed", "severity", "detail", "recommendation"}.
    """
    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, related_name="security_scans")
    scanned_at = models.DateTimeField(db_index=True)
    final_url = models.CharField(max_length=500, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    http_status = models.PositiveSmallIntegerField(null=True, blank=True)
    tls_version = models.CharField(max_length=16, blank=True)
    cipher = models.CharField(max_length=120, blank=True)
    cert_issuer = models.CharField(max_length=255, blank=True)
    cert_subject = models.CharField(max_length=255, blank=True)
    cert_expires_at = models.DateTimeField(null=True, blank=True)
    cert_days_left = models.IntegerField(null=True, blank=True)
    cert_valid = models.BooleanField(null=True)
    https_redirect = models.BooleanField(null=True)   # http:// answers with a redirect to https://
    hsts = models.CharField(max_length=500, blank=True)
    csp = models.TextField(blank=True)
    x_frame_options = models.CharField(max_length=200, blank=True)
    x_content_type_options = models.CharField(max_length=200, blank=True)
    referrer_policy = models.CharField(max_length=200, blank=True)
    permissions_policy = models.TextField(blank=True)
    server = models.CharField(max_length=200, blank=True)
    grade = models.CharField(max_length=1, blank=True, choices=[(g, g) for g in GRADES])
    score = models.PositiveSmallIntegerField(null=True, blank=True)
    findings = models.JSONField(default=list, blank=True)
    error = models.CharField(max_length=500, blank=True)

    class Meta:
        ordering = ["-scanned_at"]
        indexes = [models.Index(fields=["domain", "scanned_at"])]

    def __str__(self):
        return f"{self.domain.hostname} {self.grade or 'not graded'} @ {self.scanned_at:%Y-%m-%d %H:%M}"

    @property
    def failed(self):
        return [f for f in self.findings if not f.get("passed")]

    @property
    def passed_count(self):
        return sum(1 for f in self.findings if f.get("passed"))

    def finding(self, key):
        return next((f for f in self.findings if f.get("key") == key), None)
