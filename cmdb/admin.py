from django.contrib import admin

from .models import ConfigurationItem, License, Relationship, Software


@admin.register(ConfigurationItem)
class ConfigurationItemAdmin(admin.ModelAdmin):
    list_display = ("name", "ci_type", "status", "environment", "site", "business_domain", "owner")
    list_filter = ("ci_type", "status", "environment", "site")
    search_fields = ("name", "ip_address", "serial", "asset_tag", "business_domain", "owner")
    filter_horizontal = ("url_checks", "domains")


@admin.register(Relationship)
class RelationshipAdmin(admin.ModelAdmin):
    list_display = ("source", "rel_type", "target", "origin", "confidence")
    list_filter = ("rel_type", "origin")
    search_fields = ("source__name", "target__name", "note")
    raw_id_fields = ("source", "target")


@admin.register(Software)
class SoftwareAdmin(admin.ModelAdmin):
    list_display = ("name", "version", "vendor", "category")
    search_fields = ("name", "vendor")
    filter_horizontal = ("installs",)


@admin.register(License)
class LicenseAdmin(admin.ModelAdmin):
    list_display = ("product", "vendor", "software", "seats", "expiry")
    search_fields = ("product", "vendor", "reference")
