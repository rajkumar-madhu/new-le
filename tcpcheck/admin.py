from django.contrib import admin

from .models import SlaTarget, TcpCheck, TcpResult


@admin.register(TcpCheck)
class TcpCheckAdmin(admin.ModelAdmin):
    list_display = ("name", "host", "port", "site", "enabled", "last_status", "last_response_ms", "last_checked_at")
    list_filter = ("enabled", "last_status", "site")
    search_fields = ("name", "host", "tags")
    readonly_fields = ("last_status", "last_checked_at", "last_response_ms", "last_error", "last_ip", "last_banner",
                       "created_at", "updated_at")


@admin.register(TcpResult)
class TcpResultAdmin(admin.ModelAdmin):
    list_display = ("tcp_check", "checked_at", "status", "response_ms", "ip", "message")
    list_filter = ("status",)
    date_hierarchy = "checked_at"
    raw_id_fields = ("tcp_check",)


@admin.register(SlaTarget)
class SlaTargetAdmin(admin.ModelAdmin):
    list_display = ("kind", "object_id", "target", "updated_at")
    list_filter = ("kind",)
