from django.urls import path

from . import views

app_name = "tcpcheck"
urlpatterns = [
    path("monitoring/telnet/", views.index, name="index"),
    path("monitoring/telnet/new/", views.create, name="create"),
    path("monitoring/telnet/run/", views.run_all, name="run_all"),
    path("monitoring/telnet/export.csv", views.export_csv, name="export"),
    path("monitoring/telnet/<int:pk>/", views.detail, name="detail"),
    path("monitoring/telnet/<int:pk>/edit/", views.edit, name="edit"),
    path("monitoring/telnet/<int:pk>/delete/", views.delete, name="delete"),
    path("monitoring/telnet/<int:pk>/run/", views.run_now, name="run"),
    path("monitoring/telnet/<int:pk>/history.csv", views.history_csv, name="history_export"),
    path("monitoring/uptime/", views.uptime_view, name="uptime"),
    path("monitoring/uptime/export.csv", views.uptime_export, name="uptime_export"),
    path("monitoring/uptime/sla/", views.sla_update, name="sla"),
]
