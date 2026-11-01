from django.apps import AppConfig


class TcpcheckConfig(AppConfig):
    name = "tcpcheck"
    verbose_name = "Telnet / TCP checks"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self):
        from core.jobs import register

        from . import services
        register("tcpcheck.run_due", 15, services.run_due)
        register("tcpcheck.prune", 3600, services.prune)
