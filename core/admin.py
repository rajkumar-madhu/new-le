from django.contrib import admin

from .models import AuditEvent, Event, Membership, Site


@admin.register(Site)
class SiteAdmin(admin.ModelAdmin):
    list_display = ("name", "code", "region", "criticality", "tenant_key")
    search_fields = ("name", "code", "region")
    prepopulated_fields = {"code": ("name",)}


@admin.register(Membership)
class MembershipAdmin(admin.ModelAdmin):
    list_display = ("user", "site", "role")
    list_filter = ("role", "site")


@admin.register(AuditEvent)
class AuditEventAdmin(admin.ModelAdmin):
    list_display = ("occurred_at", "actor_name", "action", "object_type", "object_repr", "result")
    list_filter = ("action", "object_type", "result")
    search_fields = ("actor_name", "object_repr")

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(Event)
class EventAdmin(admin.ModelAdmin):
    list_display = ("occurred_at", "severity", "source", "title", "site")
    list_filter = ("severity", "source", "kind")
    search_fields = ("title", "message")
