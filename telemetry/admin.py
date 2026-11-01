from django.contrib import admin

from .models import Alert, SavedQuery


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ("alertname", "status", "severity", "instance", "job", "site", "last_received_at", "acknowledged_at")
    list_filter = ("status", "severity", "site")
    search_fields = ("alertname", "instance", "job", "fingerprint", "summary")
    readonly_fields = ("fingerprint", "labels", "annotations", "created_at", "updated_at")


@admin.register(SavedQuery)
class SavedQueryAdmin(admin.ModelAdmin):
    list_display = ("name", "owner", "shared", "range_key", "updated_at")
    list_filter = ("shared",)
    search_fields = ("name", "promql")
