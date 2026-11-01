from django.apps import AppConfig


class ServicedeskConfig(AppConfig):
    name = "servicedesk"
    verbose_name = "Service Desk"

    def ready(self):
        from core.jobs import register

        from . import signals  # noqa: F401  (connects the event listener)
        from .sla import flag_breaches
        register("servicedesk.sla", 60, flag_breaches)
