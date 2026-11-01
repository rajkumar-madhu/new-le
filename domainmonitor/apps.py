from django.apps import AppConfig


class DomainmonitorConfig(AppConfig):
    name = 'domainmonitor'
    # Keep the integer primary key created by the integration patch's 0001 migration.
    default_auto_field = 'django.db.models.AutoField'

    def ready(self):
        from core.jobs import register

        from . import security

        # Daily HTTPS security scan: the job wakes hourly and rescans each domain once its last scan is 24 h old.
        register("domainmonitor.security_scan", security.JOB_INTERVAL, security.scheduled_scan)
