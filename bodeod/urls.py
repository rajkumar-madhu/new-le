from django.urls import path

from . import views

app_name = "bodeod"
urlpatterns = [
    path("bod-eod/", views.status, name="status"),
    path("bod-eod/api/status/", views.api_status, name="api_status"),
    path("bod-eod/keys/", views.keys, name="keys"),
    path("bod-eod/history/", views.history, name="history"),
    path("bod-eod/history/export.csv", views.history_export, name="history_export"),
    path("bod-eod/modes/<int:pk>/run/", views.run_mode, name="run"),
    path("bod-eod/runs/<int:pk>/", views.detail, name="detail"),
    path("bod-eod/runs/<int:pk>/revalidate/", views.revalidate, name="revalidate"),
    path("bod-eod/results/<int:pk>/sign-off/", views.signoff, name="signoff"),
    path("bod-eod/checklist/", views.checklist, name="checklist"),
    path("bod-eod/checklist/modes/save/", views.mode_save, name="mode_save"),
    path("bod-eod/checklist/items/<int:pk>/delete/", views.item_delete, name="item_delete"),
    path("bod-eod/checklist/items/<int:pk>/move/", views.item_move, name="item_move"),
    path("bod-eod/holidays/", views.holidays, name="holidays"),
    path("bod-eod/holidays/upload/", views.holiday_upload, name="holiday_upload"),
    path("bod-eod/holidays/<int:pk>/delete/", views.holiday_delete, name="holiday_delete"),
    path("bod-eod/holidays/export.csv", views.holidays_export, name="holidays_export"),
]
