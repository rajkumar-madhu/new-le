"""Periodic job registered as `administration.heartbeat` (runs inside `manage.py run_probes`).

* Records a scheduler heartbeat so System health can tell whether run_probes is alive.
* Probe-freshness watchdog: when enabled URL/domain checks stop producing results for longer than
  services.PROBE_STALE_SECONDS it emits one warning event (fingerprint administration:probe-freshness), and an
  "ok" event when results are fresh again. State is kept in Heartbeat(key="probe-freshness") so a restart does not
  repeat the warning.
Never raises.
"""
import logging
import os
import socket

from django.utils import timezone

from .models import Heartbeat

log = logging.getLogger("linkedeye.administration")

FINGERPRINT = "administration:probe-freshness"


def _beat():
    Heartbeat.objects.update_or_create(key="scheduler", defaults={
        "seen_at": timezone.now(), "host": socket.gethostname()[:255], "pid": os.getpid()})


def _watchdog():
    from core.events import emit

    from . import services
    rows = services.probe_freshness()
    stale = [r for r in rows if r["status"] == "warn" and r["latest"] is not None]
    state = "stale" if stale else "ok"
    hb, _ = Heartbeat.objects.get_or_create(key="probe-freshness", defaults={"data": {"state": "ok"}})
    previous = (hb.data or {}).get("state", "ok")
    hb.seen_at = timezone.now()
    if state != previous:
        if state == "stale":
            detail = "; ".join(f"{r['label']}: last result {r['age_text']}" for r in stale)
            emit(source="administration", kind="health", severity="warning",
                 title="Probe results are stale",
                 message=f"{detail}. Check that manage.py run_probes is running and that probes are not hanging.",
                 fingerprint=FINGERPRINT, stale=[r["key"] for r in stale])
        else:
            emit(source="administration", kind="health", severity="ok", title="Probe results are fresh again",
                 message="URL and domain checks are producing results again.", fingerprint=FINGERPRINT)
    hb.data = {"state": state, "checked_at": timezone.now().isoformat(),
               "stale": [r["key"] for r in stale]}
    hb.save()
    return state, previous


def heartbeat():
    try:
        _beat()
        state, previous = _watchdog()
    except Exception:  # a job must never raise into the scheduler loop
        log.exception("administration.heartbeat failed")
        return "error"
    if state != previous:
        return f"probe results {state}"
    return None
