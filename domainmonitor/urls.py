from django.urls import path

from . import views

app_name = "domains"
urlpatterns = [
    path("", views.overview, name="overview"),
    path("list/", views.domain_list, name="list"),
    path("dns/", views.dns_records, name="dns"),
    path("ssl/", views.ssl_certificates, name="ssl"),
    path("export.csv", views.export_csv, name="export"),
    path("run/", views.run_all, name="run_all"),
    path("<int:pk>/toggle/", views.deactivate, name="toggle"),
    path("<int:pk>/test/<str:kind>/", views.action, name="action"),
]

# Contract kept from LinkedEye_Domains_Integration_Patch, mounted at /configuration/domains/
api_urlpatterns = [
    path("", views.page, name="linkedeye-domains-page"),
    path("api/", views.api_domains, name="linkedeye-domains-api"),
    path("api/<int:pk>/", views.api_detail, name="linkedeye-domain-detail"),
]
