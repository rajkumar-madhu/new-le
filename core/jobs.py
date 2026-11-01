"""Periodic job registry used by `manage.py run_probes`.

Apps register jobs in AppConfig.ready():
    from core.jobs import register
    register("network.poll", 60, poll_devices)
Each job is a callable taking no arguments and returning a short summary (or None).
"""
import logging
import time

log = logging.getLogger("linkedeye.jobs")

JOBS = {}


def register(name, interval_seconds, func):
    JOBS[name] = {"interval": interval_seconds, "func": func, "last": 0.0}


def run_due(now=None):
    """Run every registered job whose interval elapsed. Returns {name: summary}."""
    now = now or time.monotonic()
    done = {}
    for name, job in JOBS.items():
        if now - job["last"] < job["interval"]:
            continue
        job["last"] = now
        try:
            done[name] = job["func"]()
        except Exception:
            log.exception("job %s failed", name)
            done[name] = "error"
    return done
