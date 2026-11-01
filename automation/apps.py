from django.apps import AppConfig


class AutomationConfig(AppConfig):
    name = "automation"
    verbose_name = "Automation"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self):
        from core.jobs import register

        from . import services, signals  # noqa: F401  (connects the event_emitted receiver)
        register("automation.housekeeping", 600, services.housekeeping)
