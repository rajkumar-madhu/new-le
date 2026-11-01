from django.contrib import admin

from .models import UrlCheck, UrlResult


@admin.register(UrlCheck)
class UrlCheckAdmin(admin.ModelAdmin):
    list_display = ("name", "url", "site", "last_status", "last_response_ms", "last_checked_at", "enabled")
    list_filter = ("last_status", "site", "check_type", "enabled")
    search_fields = ("name", "url", "tags")


@admin.register(UrlResult)
class UrlResultAdmin(admin.ModelAdmin):
    list_display = ("url_check", "checked_at", "status", "http_status", "response_ms", "message")
    list_filter = ("status",)
