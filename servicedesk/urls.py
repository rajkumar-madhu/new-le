from django.urls import path

from . import views

app_name = "servicedesk"

T = "service-desk/tickets/<str:number>/"

urlpatterns = [
    path("service-desk/", views.index, name="index"),
    path("service-desk/incidents/", views.incidents, name="incidents"),
    path("service-desk/tickets/", views.tickets, name="tickets"),
    path("service-desk/tickets/export/", views.export_csv, name="export"),
    path("service-desk/tickets/new/", views.create, name="create"),
    path("service-desk/problems/", views.problems, name="problems"),
    path("service-desk/changes/", views.changes, name="changes"),
    path("service-desk/catalog/", views.catalog, name="catalog"),
    path("service-desk/catalog/new/", views.catalog_edit, name="catalog_new"),
    path("service-desk/catalog/<int:pk>/edit/", views.catalog_edit, name="catalog_edit"),
    path("service-desk/catalog/<int:pk>/delete/", views.catalog_delete, name="catalog_delete"),
    path("service-desk/catalog/<int:pk>/request/", views.catalog_request, name="catalog_request"),
    path("service-desk/sla/", views.sla_policies, name="sla"),
    path(T, views.detail, name="detail"),
    path("service-desk/<str:section>/<str:number>/", views.detail, name="detail_in"),
    path(T + "edit/", views.edit, name="edit"),
    path(T + "transition/", views.transition, name="transition"),
    path(T + "assign/", views.assign, name="assign"),
    path(T + "priority/", views.set_priority, name="priority"),
    path(T + "comment/", views.comment, name="comment"),
    path(T + "link/", views.link, name="link"),
    path(T + "cis/", views.add_ci, name="add_ci"),
    path(T + "cis/<int:pk>/remove/", views.remove_ci, name="remove_ci"),
    path(T + "delete/", views.delete, name="delete"),
]
