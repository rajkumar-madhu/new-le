from django.urls import path

from . import views, views_insights

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
    path("uptime/", views_insights.uptime, name="uptime"),
    path("performance/", views_insights.performance, name="performance"),
    path("security/", views_insights.security_page, name="security"),
    path("security/scan/", views_insights.security_scan_all, name="security_scan_all"),
    path("security/<int:pk>/scan/", views_insights.security_scan, name="security_scan"),
    path("export/", views_insights.export_reports, name="export_reports"),
]

# Contract kept from LinkedEye_Domains_Integration_Patch, mounted at /configuration/domains/
api_urlpatterns = [
    path("", views.page, name="linkedeye-domains-page"),
    path("api/", views.api_domains, name="linkedeye-domains-api"),
    path("api/<int:pk>/", views.api_detail, name="linkedeye-domain-detail"),
]
