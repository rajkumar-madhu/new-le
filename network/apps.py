from django.apps import AppConfig


class NetworkConfig(AppConfig):
    name = "network"
    verbose_name = "Network Devices"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self):
        from core.jobs import register

        from . import jobs

        register("network.reachability", 60, jobs.poll_devices)
        register("network.metrics", 60, jobs.collect_metrics)
        register("network.discovery", 30, jobs.discovery_tick)
