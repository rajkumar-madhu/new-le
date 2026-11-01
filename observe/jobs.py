"""Periodic jobs (registered in ObserveConfig.ready, run by `manage.py run_probes`).
Jobs never raise: failures are logged and reported in the summary."""
import logging

from .models import Exporter
from . import services

log = logging.getLogger("linkedeye.observe")


def exporter_health():
    """Scrape every enabled exporter that has a metrics URL; keep the others in their configuration state."""
    try:
        services.sync_config_states()
        exporters = list(Exporter.objects.filter(enabled=True).exclude(metrics_url="").order_by("pk"))
        results = services.check_exporters(exporters)
        ok = sum(1 for _e, r in results if r.ok)
        return f"scraped {len(results)} exporter(s): {ok} active, {len(results) - ok} error"
    except Exception:
        log.exception("exporter health job failed")
        return "error"


def log_retention():
    try:
        n = services.prune_logs()
        return f"pruned {n} log entr{'y' if n == 1 else 'ies'}"
    except Exception:
        log.exception("log retention job failed")
        return "error"
