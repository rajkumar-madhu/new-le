from django.contrib import admin

from .models import Execution, Rule, Runbook, Template


@admin.register(Runbook)
class RunbookAdmin(admin.ModelAdmin):
    list_display = ("title", "service", "ci_name", "site", "owner", "last_reviewed")
    list_filter = ("site",)
    search_fields = ("title", "service", "ci_name", "tags", "symptoms")


@admin.register(Rule)
class RuleAdmin(admin.ModelAdmin):
    list_display = ("name", "enabled", "match_source", "min_severity", "action", "cooldown_minutes", "last_fired_at", "fire_count")
    list_filter = ("enabled", "action", "min_severity")
    search_fields = ("name", "description", "match_source", "title_contains")


@admin.register(Execution)
class ExecutionAdmin(admin.ModelAdmin):
    list_display = ("started_at", "kind", "trigger", "status", "http_status", "rule", "triggered_by")
    list_filter = ("kind", "status")
    search_fields = ("trigger", "error", "triggered_by", "fingerprint")
    readonly_fields = [f.name for f in Execution._meta.fields]


@admin.register(Template)
class TemplateAdmin(admin.ModelAdmin):
    list_display = ("name", "kind", "applied_count", "last_applied_at")
    list_filter = ("kind",)
    search_fields = ("name", "description")
