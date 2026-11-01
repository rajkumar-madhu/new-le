from django.contrib import admin

from .models import ChecklistItem, Holiday, Mode, Run, RunItem


class ChecklistItemInline(admin.TabularInline):
    model = ChecklistItem
    extra = 0
    fields = ("order", "name", "kind", "ref_name", "critical", "enabled")


@admin.register(Mode)
class ModeAdmin(admin.ModelAdmin):
    list_display = ("code", "name", "window_start", "window_end", "auto_run_time", "enabled", "site")
    list_filter = ("enabled", "site")
    inlines = [ChecklistItemInline]


@admin.register(ChecklistItem)
class ChecklistItemAdmin(admin.ModelAdmin):
    list_display = ("name", "mode", "order", "kind", "ref_name", "critical", "enabled")
    list_filter = ("mode", "kind", "critical", "enabled")
    search_fields = ("name", "ref_name")


class RunItemInline(admin.TabularInline):
    model = RunItem
    extra = 0
    fields = ("order", "name", "kind", "ref_name", "critical", "status", "detail", "signed_off_by_name", "signed_off_at", "note")
    readonly_fields = fields
    can_delete = False


@admin.register(Run)
class RunAdmin(admin.ModelAdmin):
    list_display = ("pk", "mode", "trading_date", "started_at", "finished_at", "trigger", "triggered_by_name", "status")
    list_filter = ("mode", "status", "trigger")
    date_hierarchy = "trading_date"
    inlines = [RunItemInline]


@admin.register(Holiday)
class HolidayAdmin(admin.ModelAdmin):
    list_display = ("date", "exchange", "description", "source")
    list_filter = ("exchange", "source")
    search_fields = ("description",)
