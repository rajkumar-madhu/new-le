from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import include, path

from core import views as core
from domainmonitor.urls import api_urlpatterns as domain_api

admin.site.site_header = "LinkedEye administration"
admin.site.site_title = "LinkedEye"

urlpatterns = [
    path("", core.dashboard, name="dashboard"),
    path("search/", core.search, name="search"),
    path("healthz", core.healthz, name="healthz"),
    path("accounts/login/", auth_views.LoginView.as_view(), name="login"),
    path("accounts/logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("monitoring/url-checker/", include("urlchecker.urls")),
    path("legacy/heatmap/", core.heatmap, name="heatmap"),
    path("legacy/exporters/", core.exporters, name="exporters"),
    path("legacy/incidents/", core.incidents, name="incidents"),
    path("legacy/fg-01/", core.firewall, name="firewall"),
    path("domains/", include("domainmonitor.urls")),
    path("configuration/domains/", include(domain_api)),
    # module apps define full paths in their own urls.py
    path("", include("servicedesk.urls")),
    path("", include("cmdb.urls")),
    path("", include("network.urls")),
    path("", include("telemetry.urls")),
    path("", include("observe.urls")),
    path("", include("tcpcheck.urls")),
    path("", include("bodeod.urls")),
    path("", include("automation.urls")),
    path("", include("administration.urls")),
    path("soon/<slug:slug>/", core.coming_soon, name="coming_soon"),
    path("admin/", admin.site.urls),
]
