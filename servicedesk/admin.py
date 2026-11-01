from django.contrib import admin

from .models import CatalogItem, SlaPolicy, Ticket, TicketCI, TimelineEntry


@admin.register(SlaPolicy)
class SlaPolicyAdmin(admin.ModelAdmin):
    list_display = ("priority", "name", "response_minutes", "resolution_minutes", "active", "tenant_key")
    list_filter = ("active", "tenant_key")


@admin.register(CatalogItem)
class CatalogItemAdmin(admin.ModelAdmin):
    list_display = ("name", "category", "fulfilment_hours", "default_priority", "active")
    list_filter = ("active", "category")
    search_fields = ("name", "description")


class TimelineInline(admin.TabularInline):
    model = TimelineEntry
    extra = 0
    fields = ("created_at", "kind", "author_name", "body")
    readonly_fields = fields


class CIInline(admin.TabularInline):
    model = TicketCI
    extra = 0


@admin.register(Ticket)
class TicketAdmin(admin.ModelAdmin):
    list_display = ("number", "title", "kind", "status", "priority", "site", "assignee", "opened_at", "response_breached", "resolution_breached")
    list_filter = ("kind", "status", "priority", "source", "response_breached", "resolution_breached")
    search_fields = ("number", "title", "description", "fingerprint", "ci_name")
    raw_id_fields = ("problem", "catalog_item", "assignee", "reporter", "approved_by")
    readonly_fields = ("number", "seq")
    inlines = [CIInline, TimelineInline]
