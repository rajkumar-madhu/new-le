"""Periodic jobs registered with core.jobs (run by `manage.py run_probes`). Jobs never raise."""
import logging

log = logging.getLogger("linkedeye.telemetry")


def prune_alerts():
    """Delete resolved Alertmanager alerts older than TELEMETRY_ALERT_RETENTION_DAYS (default 90)."""
    from .alerts import prune
    try:
        n = prune()
    except Exception:
        log.exception("telemetry.prune_alerts failed")
        return "error"
    return f"pruned {n} resolved alert(s)"
