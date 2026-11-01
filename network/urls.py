from django.urls import path

from . import views

app_name = "network"
urlpatterns = [
    path("network/switches/", views.switches, name="switches"),
    path("network/routers/", views.routers, name="routers"),
    path("network/firewalls/", views.firewalls, name="firewalls"),
    path("network/load-balancers/", views.load_balancers, name="load_balancers"),
    path("network/wireless/", views.wireless, name="wireless"),
    path("network/physical-servers/", views.physical_servers, name="physical_servers"),
    path("network/virtual-machines/", views.virtual_machines, name="virtual_machines"),
    path("network/devices/", views.device_list, name="all"),
    path("network/devices/new/", views.device_form, name="create"),
    path("network/devices/export.csv", views.export_csv, name="export"),
    path("network/devices/check/", views.check_all, name="check_all"),
    path("network/devices/<int:pk>/", views.detail, name="detail"),
    path("network/devices/<int:pk>/edit/", views.device_form, name="edit"),
    path("network/devices/<int:pk>/delete/", views.device_delete, name="delete"),
    path("network/devices/<int:pk>/check/", views.check_now, name="check"),
    path("network/devices/<int:pk>/interfaces.csv", views.interfaces_csv, name="interfaces_export"),
    path("network/discovery/", views.discovery_view, name="discovery"),
    path("network/discovery/<int:pk>/", views.discovery_run, name="discovery_run"),
    path("network/discovery/<int:pk>/approve/", views.discovery_approve, name="discovery_approve"),
    path("network/discovery/<int:pk>/ignore/", views.discovery_ignore, name="discovery_ignore"),
    path("network/discovery/<int:pk>/cancel/", views.discovery_cancel, name="discovery_cancel"),
]
