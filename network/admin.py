from django.contrib import admin

from .models import Device, DevicePoll, DiscoveredHost, DiscoveryRun, Interface


class InterfaceInline(admin.TabularInline):
    model = Interface
    extra = 0
    readonly_fields = ["if_index", "name", "alias", "if_type", "admin_status", "oper_status", "speed_mbps", "in_mbps",
                       "out_mbps", "utilization", "updated_at"]
    can_delete = False


@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = ["name", "device_type", "vendor", "model", "mgmt_ip", "site", "status", "last_seen", "enabled"]
    list_filter = ["device_type", "status", "enabled", "environment", "site"]
    search_fields = ["name", "mgmt_ip", "vendor", "model", "serial", "tags"]
    readonly_fields = ["status", "last_seen", "last_checked_at", "last_latency_ms", "last_error", "status_changed_at",
                       "consecutive_failures", "uptime_seconds", "metrics_updated_at", "metrics_error", "created_at", "updated_at"]
    inlines = [InterfaceInline]


@admin.register(DevicePoll)
class DevicePollAdmin(admin.ModelAdmin):
    list_display = ["device", "checked_at", "status", "latency_ms", "error"]
    list_filter = ["status"]
    date_hierarchy = "checked_at"


class DiscoveredHostInline(admin.TabularInline):
    model = DiscoveredHost
    extra = 0
    readonly_fields = ["ip", "open_ports", "latency_ms", "status", "device", "decided_by_name", "decided_at"]


@admin.register(DiscoveryRun)
class DiscoveryRunAdmin(admin.ModelAdmin):
    list_display = ["id", "cidr", "ports", "status", "found", "requested_by_name", "created_at"]
    list_filter = ["status"]
    inlines = [DiscoveredHostInline]
