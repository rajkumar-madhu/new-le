from django.apps import AppConfig


class TelemetryConfig(AppConfig):
    name = "telemetry"
    verbose_name = "Telemetry (Prometheus, Alertmanager, Nagios)"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self):
        from core.jobs import register

        from . import jobs
        register("telemetry.prune_alerts", 3600, jobs.prune_alerts)
