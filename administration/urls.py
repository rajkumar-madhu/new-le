from django.urls import path

from . import views

app_name = "administration"
urlpatterns = [
    path("administration/", views.index, name="index"),
    path("administration/profile/", views.profile, name="profile"),
    path("administration/users/", views.users, name="users"),
    path("administration/users/export.csv", views.users_export, name="users_export"),
    path("administration/users/new/", views.user_create, name="user_create"),
    path("administration/users/<int:pk>/", views.user_edit, name="user_edit"),
    path("administration/users/<int:pk>/memberships/", views.membership_save, name="membership_save"),
    path("administration/users/<int:pk>/memberships/<int:mid>/remove/", views.membership_remove, name="membership_remove"),
    path("administration/users/<int:pk>/active/", views.user_toggle_active, name="user_toggle_active"),
    path("administration/users/<int:pk>/password/", views.user_password, name="user_password"),
    path("administration/sites/", views.sites, name="sites"),
    path("administration/sites/new/", views.site_create, name="site_create"),
    path("administration/sites/bootstrap/", views.sites_bootstrap, name="sites_bootstrap"),
    path("administration/sites/<int:pk>/", views.site_edit, name="site_edit"),
    path("administration/sites/<int:pk>/delete/", views.site_delete, name="site_delete"),
    path("administration/audit/", views.audit_log, name="audit"),
    path("administration/audit/export.csv", views.audit_export, name="audit_export"),
    path("administration/integrations/", views.integrations, name="integrations"),
    path("administration/integrations/<slug:key>/test/", views.integration_test, name="integration_test"),
    path("administration/health/", views.health, name="health"),
]
