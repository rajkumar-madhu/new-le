from django.urls import path

from . import views

app_name = "cmdb"
urlpatterns = [
    # Assets
    path("assets/", views.assets, name="assets"),
    path("assets/export.csv", views.items_export, {"hardware": True}, name="assets_export"),
    path("assets/import/", views.items_import, {"assets": True}, name="assets_import"),
    path("assets/software/", views.software, name="software"),
    path("assets/software/new/", views.software_form, name="software_create"),
    path("assets/software/export.csv", views.software_export, name="software_export"),
    path("assets/software/<int:pk>/", views.software_detail, name="software_detail"),
    path("assets/software/<int:pk>/edit/", views.software_form, name="software_edit"),
    path("assets/software/<int:pk>/installs/", views.software_installs, name="software_installs"),
    path("assets/software/<int:pk>/delete/", views.software_delete, name="software_delete"),
    path("assets/licenses/", views.licenses, name="licenses"),
    path("assets/licenses/new/", views.license_form, name="license_create"),
    path("assets/licenses/export.csv", views.licenses_export, name="licenses_export"),
    path("assets/licenses/<int:pk>/edit/", views.license_form, name="license_edit"),
    path("assets/licenses/<int:pk>/delete/", views.license_delete, name="license_delete"),
    path("assets/lifecycle/", views.lifecycle, name="lifecycle"),
    path("assets/lifecycle/export.csv", views.lifecycle_export, name="lifecycle_export"),
    # CMDB
    path("cmdb/topology/", views.topology_view, name="topology"),
    path("cmdb/items/", views.items, name="items"),
    path("cmdb/items/new/", views.item_form, name="item_create"),
    path("cmdb/items/export.csv", views.items_export, name="items_export"),
    path("cmdb/items/import/", views.items_import, name="items_import"),
    path("cmdb/items/import/template.csv", views.import_template, name="import_template"),
    path("cmdb/items/<int:pk>/", views.item_detail, name="item_detail"),
    path("cmdb/items/<int:pk>/edit/", views.item_form, name="item_edit"),
    path("cmdb/items/<int:pk>/delete/", views.item_delete, name="item_delete"),
    path("cmdb/relationships/", views.relationships, name="relationships"),
    path("cmdb/relationships/new/", views.relationship_create, name="relationship_create"),
    path("cmdb/relationships/export.csv", views.relationships_export, name="relationships_export"),
    path("cmdb/relationships/<int:pk>/delete/", views.relationship_delete, name="relationship_delete"),
    # Monitoring
    path("monitoring/heatmap/", views.heatmap_view, name="heatmap"),
]
