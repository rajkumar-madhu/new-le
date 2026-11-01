from django.apps import AppConfig


class ObserveConfig(AppConfig):
    name = "observe"
    verbose_name = "Exporters, Logs & Events"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self):
        from core.jobs import register

        from . import jobs

        register("observe.exporter_health", 60, jobs.exporter_health)
        register("observe.log_retention", 3600, jobs.log_retention)
