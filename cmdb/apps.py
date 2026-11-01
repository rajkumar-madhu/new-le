from django.apps import AppConfig


class CmdbConfig(AppConfig):
    name = "cmdb"
    verbose_name = "CMDB & Assets"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self):
        from core.jobs import register

        from . import jobs, listeners  # noqa: F401 - connects the event listener

        register("cmdb.lifecycle", 3600, jobs.lifecycle_scan)
