from django.apps import AppConfig


class CoreConfig(AppConfig):
    name = "core"
    verbose_name = "LinkedEye core"

    def ready(self):
        from . import notify  # noqa: F401  (registers the notification listener)
