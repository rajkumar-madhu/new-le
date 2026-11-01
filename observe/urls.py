from django.urls import path

from . import views

app_name = "observe"
urlpatterns = [
    # exporters
    path("monitoring/exporters/", views.exporters, name="exporters"),
    path("monitoring/exporters/new/", views.exporter_form, name="exporter_create"),
    path("monitoring/exporters/check/", views.exporter_check_all, name="exporter_check_all"),
    path("monitoring/exporters/export.csv", views.exporters_export, name="exporters_export"),
    path("monitoring/exporters/import/", views.exporters_import, name="exporters_import"),
    path("monitoring/exporters/docs/", views.exporters_docs, name="docs"),
    path("monitoring/exporters/<int:pk>/", views.exporter_detail, name="exporter_detail"),
    path("monitoring/exporters/<int:pk>/edit/", views.exporter_form, name="exporter_edit"),
    path("monitoring/exporters/<int:pk>/delete/", views.exporter_delete, name="exporter_delete"),
    path("monitoring/exporters/<int:pk>/check/", views.exporter_check, name="exporter_check"),
    # logs & events
    path("logs/", views.logs, name="logs"),
    path("logs/feed/", views.logs_feed, name="logs_feed"),
    path("logs/export.csv", views.logs_export, name="logs_export"),
    path("logs/events/", views.events, name="events"),
    path("logs/events/export.csv", views.events_export, name="events_export"),
    # machine-to-machine ingest (bearer token, no session/CSRF)
    path("api/v1/logs/", views.log_ingest, name="log_ingest"),
]
