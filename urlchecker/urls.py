from django.urls import path

from . import views

app_name = "urlchecker"
urlpatterns = [
    path("", views.index, name="index"),
    path("<int:pk>/edit/", views.index, name="edit"),
    path("<int:pk>/", views.detail, name="detail"),
    path("<int:pk>/run/", views.run_now, name="run"),
    path("run/", views.run_now, name="run_all"),
    path("<int:pk>/delete/", views.delete, name="delete"),
    path("export.csv", views.export_csv, name="export"),
]
