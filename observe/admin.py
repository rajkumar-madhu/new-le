from django.contrib import admin

from .models import Exporter, LogEntry


@admin.register(Exporter)
class ExporterAdmin(admin.ModelAdmin):
    list_display = ("name", "exporter_type", "category", "target", "site", "enabled", "status", "last_seen", "samples")
    list_filter = ("category", "status", "enabled", "site")
    search_fields = ("name", "exporter_type", "target", "metrics_url")
    readonly_fields = ("status", "status_changed_at", "last_checked_at", "last_seen", "last_scrape_ms", "samples",
                       "last_error", "created_at", "updated_at")


@admin.register(LogEntry)
class LogEntryAdmin(admin.ModelAdmin):
    list_display = ("ts", "level", "source", "host", "site", "short_message")
    list_filter = ("level", "site")
    search_fields = ("source", "host", "message")
    date_hierarchy = "ts"

    @admin.display(description="Message")
    def short_message(self, obj):
        return obj.message[:120]
