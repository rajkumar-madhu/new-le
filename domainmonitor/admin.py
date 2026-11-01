from django.contrib import admin

from .models import Domain, DomainCheck


@admin.register(Domain)
class DomainAdmin(admin.ModelAdmin):
    list_display = ("hostname", "tenant_key", "site_key", "domain_type", "status", "dns_status", "ssl_status", "is_active")
    list_filter = ("status", "ssl_status", "dns_status", "domain_type", "is_active")
    search_fields = ("hostname", "description")


@admin.register(DomainCheck)
class DomainCheckAdmin(admin.ModelAdmin):
    list_display = ("domain", "checked_at", "up", "http_status", "response_ms", "dns_status", "ssl_status")
    list_filter = ("up", "ssl_status")
