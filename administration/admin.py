from django.contrib import admin

from .models import Heartbeat, IntegrationTest


@admin.register(IntegrationTest)
class IntegrationTestAdmin(admin.ModelAdmin):
    list_display = ("tested_at", "integration", "ok", "tested_by_name", "message")
    list_filter = ("integration", "ok")
    readonly_fields = [f.name for f in IntegrationTest._meta.fields]

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(Heartbeat)
class HeartbeatAdmin(admin.ModelAdmin):
    list_display = ("key", "seen_at", "host", "pid")
    readonly_fields = ("key", "seen_at", "host", "pid", "data")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
