from django.apps import AppConfig


class AdministrationConfig(AppConfig):
    name = "administration"
    verbose_name = "Administration"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self):
        from core.jobs import register

        from . import jobs, signals  # noqa: F401  (connects the sign-in audit receivers)
        register("administration.heartbeat", 60, jobs.heartbeat)
