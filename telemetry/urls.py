from django.urls import path

from . import views

app_name = "telemetry"

urlpatterns = [
    path("monitoring/infrastructure/", views.infrastructure, name="infrastructure"),
    path("monitoring/infrastructure/<path:instance>/", views.host_detail, name="host_detail"),
    path("monitoring/nagios/", views.nagios_status, name="nagios"),
    path("monitoring/prometheus/", views.prometheus_targets, name="prometheus"),
    path("monitoring/alerts/", views.alert_list, name="alertmanager"),
    path("monitoring/alerts/acknowledge/", views.acknowledge, name="alert_ack_bulk"),
    path("monitoring/alerts/<int:pk>/", views.alert_detail, name="alert_detail"),
    path("monitoring/alerts/<int:pk>/acknowledge/", views.acknowledge, name="alert_ack"),
    path("monitoring/alerts/<int:pk>/unacknowledge/", views.unacknowledge, name="alert_unack"),
    path("monitoring/metrics-explorer/", views.explorer, name="explorer"),
    path("monitoring/metrics-explorer/save/", views.save_query, name="query_save"),
    path("monitoring/metrics-explorer/<int:pk>/delete/", views.delete_query, name="query_delete"),
    path("api/v1/alertmanager/", views.alertmanager_webhook, name="alertmanager_webhook"),
]
