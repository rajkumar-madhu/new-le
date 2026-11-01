from django.contrib import admin

from .models import ReportRun, ScheduledReport


@admin.register(ScheduledReport)
class ScheduledReportAdmin(admin.ModelAdmin):
    list_display = ("name", "report_key", "frequency", "send_hour", "enabled", "owner", "next_run_at", "last_status")
    list_filter = ("report_key", "frequency", "enabled", "last_status")
    search_fields = ("name", "recipients")


@admin.register(ReportRun)
class ReportRunAdmin(admin.ModelAdmin):
    list_display = ("report_key", "channel", "status", "rows", "requested_by_name", "created_at")
    list_filter = ("report_key", "channel", "status")
    readonly_fields = [f.name for f in ReportRun._meta.fields]
