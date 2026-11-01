from django.apps import AppConfig


class DomainmonitorConfig(AppConfig):
    name = 'domainmonitor'
    # Keep the integer primary key created by the integration patch's 0001 migration.
    default_auto_field = 'django.db.models.AutoField'
