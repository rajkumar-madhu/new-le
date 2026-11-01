"""Platform-wide models: sites and role memberships, the audit trail and the
unified event stream that every module writes to."""
from django.conf import settings
from django.db import models
from django.utils import timezone


class Site(models.Model):
    """A customer site / location (e.g. Mumbai (NSE), DR Site). Other modules
    reference sites by name for compatibility with the original LinkedEye data."""
    CRITICALITY = [("critical", "Critical"), ("high", "High"), ("standard", "Standard"), ("low", "Low")]

    tenant_key = models.CharField(max_length=100, db_index=True, default=settings.LINKEDEYE_TENANT)
    name = models.CharField(max_length=100)
    code = models.SlugField(max_length=60)
    region = models.CharField(max_length=100, blank=True)
    timezone = models.CharField(max_length=60, default="Asia/Kolkata")
    criticality = models.CharField(max_length=10, choices=CRITICALITY, default="standard")
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]
        constraints = [models.UniqueConstraint(fields=["tenant_key", "name"], name="site_tenant_name_unique"),
                       models.UniqueConstraint(fields=["tenant_key", "code"], name="site_tenant_code_unique")]

    def __str__(self):
        return self.name


class Membership(models.Model):
    """Grants a user a role, either on one site or (site=None) on every site of the tenant."""
    ROLES = [("admin", "Admin"), ("operator", "Operator"), ("viewer", "Viewer")]

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="le_memberships")
    site = models.ForeignKey(Site, on_delete=models.CASCADE, null=True, blank=True, related_name="memberships")
    role = models.CharField(max_length=10, choices=ROLES, default="viewer")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["user", "site"], name="membership_user_site_unique")]

    def __str__(self):
        return f"{self.user} · {self.site or 'All sites'} · {self.role}"


class AuditEvent(models.Model):
    """Append-only record of who changed what."""
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    actor_name = models.CharField(max_length=150, blank=True)
    action = models.CharField(max_length=60)
    object_type = models.CharField(max_length=60)
    object_id = models.CharField(max_length=64, blank=True)
    object_repr = models.CharField(max_length=200, blank=True)
    result = models.CharField(max_length=20, default="ok")
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    details = models.JSONField(default=dict, blank=True)
    occurred_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        ordering = ["-occurred_at"]

    def __str__(self):
        return f"{self.actor_name} {self.action} {self.object_type}:{self.object_id}"


class Event(models.Model):
    """Unified operational event: state changes from probes, alerts from
    Alertmanager, device reachability, BOD/EOD runs, automation results…"""
    SEVERITY = [("critical", "Critical"), ("warning", "Warning"), ("info", "Info"), ("ok", "Resolved")]

    tenant_key = models.CharField(max_length=100, db_index=True, default=settings.LINKEDEYE_TENANT)
    occurred_at = models.DateTimeField(default=timezone.now, db_index=True)
    severity = models.CharField(max_length=10, choices=SEVERITY, default="info")
    source = models.CharField(max_length=40, db_index=True)        # app label, e.g. "urlchecker"
    kind = models.CharField(max_length=40, default="state_change")  # state_change | alert | log | job | ...
    title = models.CharField(max_length=200)
    message = models.TextField(blank=True)
    site = models.CharField(max_length=100, blank=True, db_index=True)
    object_type = models.CharField(max_length=60, blank=True)
    object_id = models.CharField(max_length=64, blank=True)
    fingerprint = models.CharField(max_length=200, blank=True, db_index=True)
    data = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-occurred_at"]
        indexes = [models.Index(fields=["tenant_key", "occurred_at"])]

    def __str__(self):
        return f"[{self.severity}] {self.title}"
