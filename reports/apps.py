from django.apps import AppConfig


class ReportsConfig(AppConfig):
    name = "reports"
    verbose_name = "Reports & Analytics"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self):
        from core.jobs import register
        from . import scheduler
        register("reports.scheduled", 300, scheduler.run_due_schedules)
