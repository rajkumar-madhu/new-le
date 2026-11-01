#!/usr/bin/env python3
"""Health check for the LinkedEye container image (Docker HEALTHCHECK, compose healthcheck, Kubernetes exec probe).

    python deploy/docker/healthcheck.py           web process: GET /healthz on the local gunicorn must answer 200
    python deploy/docker/healthcheck.py probes    scheduler (manage.py run_probes): its heartbeat must be fresh
    python deploy/docker/healthcheck.py preflight no LINKEDEYE_* variable may still hold a "<REPLACE ...>"
                                                  placeholder from secret.template.yaml (init containers,
                                                  migration Job and gunicorn start-up run this)

Exit status 0 = healthy, 1 = unhealthy; one line of explanation goes to stdout (Docker shows it in
`docker inspect`).

web
    Connects to the first TCP address in GUNICORN_BIND (default 0.0.0.0:8000; a wildcard address means
    loopback). Django rejects unknown Host headers, so the request carries the first usable entry of
    LINKEDEYE_ALLOWED_HOSTS ("localhost" when unset).
    /healthz is public and checks the database connection.

probes
    The administration app's `administration.heartbeat` job (run by run_probes every 60 s) stores
    Heartbeat(key="scheduler") with this container's hostname. Healthy when that row was written by this
    host less than HEALTHCHECK_MAX_HEARTBEAT_AGE seconds ago (default 300). This catches a scheduler loop that
    hangs as well as one that died. If the administration app is not installed, the check falls back to
    "the database is reachable".
"""
import http.client
import os
import socket
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]  # /app


def _host_header():
    for entry in os.environ.get("LINKEDEYE_ALLOWED_HOSTS", "").split(","):
        entry = entry.strip().lstrip(".")
        if entry and entry != "*" and "*" not in entry:
            return entry
    return "localhost"


PLACEHOLDER_MARK = "<REPLACE"


def placeholder_variables(environ):
    """Names of LINKEDEYE_* variables whose value is still a secret.template.yaml placeholder."""
    return sorted(k for k, v in environ.items() if k.startswith("LINKEDEYE_") and PLACEHOLDER_MARK in (v or ""))


def _target(bind=None):
    """(address, port) to probe: the first TCP entry of GUNICORN_BIND; wildcard addresses map to loopback."""
    if bind is None:
        bind = os.environ.get("GUNICORN_BIND", "")
    for entry in (bind or "0.0.0.0:8000").split(","):
        entry = entry.strip()
        if not entry or entry.startswith(("unix:", "fd://")):
            continue
        host, sep, port = entry.rpartition(":")
        if not sep:  # bare host name, gunicorn's default port
            host, port = entry, "8000"
        host = host.strip("[]")
        try:
            port = int(port)
        except ValueError:
            continue
        if host in ("", "0.0.0.0", "*"):
            host = "127.0.0.1"
        elif host == "::":
            host = "::1"
        return host, port
    return "127.0.0.1", 8000


def check_web(timeout=4.0):
    host, port = _target()
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", "/healthz", headers={"Host": _host_header(), "User-Agent": "linkedeye-healthcheck"})
        resp = conn.getresponse()
        body = resp.read(512).decode("utf-8", "replace")
    except OSError as exc:
        return False, f"web: /healthz unreachable on {host} port {port}: {exc}"
    finally:
        conn.close()
    if resp.status != 200:
        hint = " (Host header rejected: check LINKEDEYE_ALLOWED_HOSTS)" if resp.status == 400 else ""
        return False, f"web: /healthz returned HTTP {resp.status}{hint}"
    return True, f"web: ok {body.strip()[:80]}"


def check_probes(max_age=None):
    if max_age is None:
        try:
            max_age = int(os.environ.get("HEALTHCHECK_MAX_HEARTBEAT_AGE", "300"))
        except ValueError:
            max_age = 300
    sys.path.insert(0, str(BASE_DIR))
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "linkedeye.settings")
    try:
        import django
        django.setup()
        from django.apps import apps
        from django.db import connection
        from django.utils import timezone

        connection.ensure_connection()
        try:
            Heartbeat = apps.get_model("administration", "Heartbeat")
        except LookupError:
            return True, "probes: database reachable (administration app absent, no heartbeat to check)"
        beat = Heartbeat.objects.filter(key="scheduler").values("seen_at", "host").first()
    except Exception as exc:  # any setup/database error means unhealthy, never a traceback
        return False, f"probes: {type(exc).__name__}: {str(exc)[:200]}"
    if not beat:
        return False, "probes: no scheduler heartbeat recorded yet"
    age = (timezone.now() - beat["seen_at"]).total_seconds()
    me = socket.gethostname()[:255]
    if beat["host"] and beat["host"] != me:
        return False, (f"probes: last heartbeat came from {beat['host']!r}, not this container ({me!r}), "
                       f"{age:.0f}s ago; is a second scheduler running?")
    if age > max_age:
        return False, f"probes: last heartbeat {age:.0f}s ago (limit {max_age}s); run_probes is stalled"
    return True, f"probes: heartbeat {age:.0f}s ago"


def check_preflight(environ=None):
    unedited = placeholder_variables(os.environ if environ is None else environ)
    if unedited:
        return False, ("preflight: these variables still hold '<REPLACE ...>' placeholders from "
                       "secret.template.yaml; set real values: " + ", ".join(unedited))
    return True, "preflight: ok"


def main(argv):
    mode = argv[1] if len(argv) > 1 else "web"
    checks = {"web": check_web, "probes": check_probes, "preflight": check_preflight}
    if mode not in checks:
        print(f"usage: {argv[0]} [web|probes|preflight]")
        return 2
    ok, message = checks[mode]()
    print(message)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
