from django.urls import path

from . import views

app_name = "reports"

urlpatterns = [
    path("analytics/", views.analytics, name="analytics"),
    path("reports/", views.index, name="index"),
    path("reports/schedules/new/", views.schedule_form, name="schedule_new"),
    path("reports/schedules/<int:pk>/edit/", views.schedule_form, name="schedule_edit"),
    path("reports/schedules/<int:pk>/delete/", views.schedule_delete, name="schedule_delete"),
    path("reports/schedules/<int:pk>/send/", views.schedule_send, name="schedule_send"),
    path("reports/<slug:key>/", views.preview, name="preview"),
    path("reports/<slug:key>/download.csv", views.download, name="download"),
]
