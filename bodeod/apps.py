from django.apps import AppConfig


class BodeodConfig(AppConfig):
    name = "bodeod"
    verbose_name = "BOD / EOD validation"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self):
        from core.jobs import register

        from . import services
        register("bodeod.auto_run", 60, services.auto_run)
