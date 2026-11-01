from django.contrib import admin

from .models import Domain, DomainCheck, DomainSecurityScan


@admin.register(Domain)
class DomainAdmin(admin.ModelAdmin):
    list_display = ("hostname", "tenant_key", "site_key", "domain_type", "status", "dns_status", "ssl_status", "is_active")
    list_filter = ("status", "ssl_status", "dns_status", "domain_type", "is_active")
    search_fields = ("hostname", "description")


@admin.register(DomainCheck)
class DomainCheckAdmin(admin.ModelAdmin):
    list_display = ("domain", "checked_at", "up", "http_status", "response_ms", "dns_status", "ssl_status")
    list_filter = ("up", "ssl_status")


@admin.register(DomainSecurityScan)
class DomainSecurityScanAdmin(admin.ModelAdmin):
    list_display = ("domain", "scanned_at", "grade", "score", "tls_version", "cert_days_left", "error")
    list_filter = ("grade", "tls_version")
    search_fields = ("domain__hostname", "cert_issuer", "server")
    raw_id_fields = ("domain",)
