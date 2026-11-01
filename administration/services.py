"""Administration services: global-admin checks, password generation, integration status and tests, system
health. Everything here is safe to call from a view: functions never raise for an unreachable integration and
never return secret values (tokens, API keys, passwords, webhook paths)."""
import io
import logging
import os
import platform
import secrets
import socket
import string
import sys
import time
import urllib.error
import urllib.request
from datetime import timedelta
from urllib.parse import urlsplit

import django
from django.apps import apps
from django.conf import settings
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.db import connection
from django.db.models import Count
from django.utils import timezone

from .models import Heartbeat, IntegrationTest

log = logging.getLogger("linkedeye.administration")

PROBE_STALE_SECONDS = 600          # probe results older than this are stale ("warn if > 10 min old")
HEARTBEAT_INTERVAL = 60            # administration.heartbeat job interval
HEARTBEAT_STALE_SECONDS = 3 * HEARTBEAT_INTERVAL
TEST_TIMEOUT = 5
ROLE_LABELS = dict([("admin", "Admin"), ("operator", "Operator"), ("viewer", "Viewer")])


def tenant():
    return settings.LINKEDEYE_TENANT


# ------------------------------------------------------------------ access
def is_global_admin(user):
    """Admin console access: superusers, or users holding the admin role on *All sites*.

    A site-scoped admin passes core.access.can(user, "admin") but must not manage users, sites or integrations of
    the whole tenant (that would let them grant themselves wider access)."""
    if not user or not user.is_authenticated or not user.is_active:
        return False
    if user.is_superuser:
        return True
    from core.models import Membership
    return Membership.objects.filter(user=user, site__isnull=True, role="admin").exists()


def effective_role(user):
    """(role, note) for display: what core.access grants this user anywhere."""
    if user.is_superuser:
        return "admin", "Superuser"
    ms = list(user.le_memberships.all())
    if not ms:
        return ("operator", "Staff default") if user.is_staff else ("viewer", "Default")
    best = max(ms, key=lambda m: {"viewer": 1, "operator": 2, "admin": 3}[m.role])
    return best.role, ""


def forget_access_cache(user):
    """core.access caches memberships on the user object; drop it after changing them."""
    if hasattr(user, "_le_memberships"):
        del user._le_memberships


# ------------------------------------------------------------------ passwords
PASSWORD_ALPHABET = string.ascii_letters + string.digits + "-_.!@#%+="


def generate_password(user=None, length=20):
    """A random password that satisfies AUTH_PASSWORD_VALIDATORS (retries until it does)."""
    for _ in range(50):
        pw = "".join(secrets.choice(PASSWORD_ALPHABET) for _ in range(length))
        if not (any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw)):
            continue
        try:
            validate_password(pw, user)
            return pw
        except ValidationError:
            continue
    raise RuntimeError("could not generate a password that passes the configured validators")


# ------------------------------------------------------------------ helpers
def safe_url(url):
    """scheme://host[:port]/path without credentials, query or fragment (for display)."""
    url = str(url or "").strip()
    if not url:
        return ""
    try:
        p = urlsplit(url)
        host = p.hostname or ""
        if p.port:
            host += f":{p.port}"
    except ValueError:
        return "(invalid URL)"
    if not p.scheme or not host:
        return "(invalid URL)"
    return f"{p.scheme}://{host}{p.path}"


def url_host(url):
    try:
        p = urlsplit(str(url or "").strip())
        return p.hostname or "(invalid URL)"
    except ValueError:
        return "(invalid URL)"


def _setting(name, default=""):
    """Setting value, falling back to the LINKEDEYE_<NAME> environment variable (as telemetry.nagios does)."""
    v = getattr(settings, name, None)
    if v in (None, ""):
        v = os.environ.get(f"LINKEDEYE_{name}", default)
    return v


def _reverse(name):
    from django.urls import NoReverseMatch, reverse
    try:
        return reverse(name)
    except NoReverseMatch:
        return ""


def _latest_event(**filters):
    from core.models import Event
    return Event.objects.filter(tenant_key=tenant(), **filters).order_by("-occurred_at").values_list("occurred_at", flat=True).first()


def _token_detail(token):
    if not token:
        return "Not set"
    if len(token) < 24:
        return f"Set ({len(token)} characters; use at least 24)"
    return "Set"


def last_tests():
    out = {}
    for t in IntegrationTest.objects.filter(tenant_key=tenant()).order_by("-tested_at")[:200]:
        out.setdefault(t.integration, t)
    return out


# ------------------------------------------------------------------ integrations
def integrations():
    """Status of every external integration. Never includes secret values."""
    tests = last_tests()
    items = []

    prom = settings.PROMETHEUS_URL
    items.append({
        "key": "prometheus", "name": "Prometheus", "icon": "activity", "configured": bool(prom),
        "purpose": "Metrics, targets and alerts for the Monitoring pages.",
        "env": ["LINKEDEYE_PROMETHEUS_URL", "LINKEDEYE_PROMETHEUS_TIMEOUT"],
        "details": [("Server", safe_url(prom) or "–"), ("Timeout", f"{settings.PROMETHEUS_TIMEOUT:g} s")],
        "testable": True, "test_label": "Run 'up' query", "last_test": tests.get("prometheus"),
    })

    am = getattr(settings, "ALERTMANAGER_WEBHOOK_TOKEN", "")
    am_url = _reverse("telemetry:alertmanager_webhook") or "/api/v1/alertmanager/"
    last_alert = _latest_event(source="telemetry", kind="alert")
    items.append({
        "key": "alertmanager", "name": "Alertmanager webhook", "icon": "bell", "configured": bool(am),
        "purpose": "Alertmanager posts firing/resolved alerts here with this bearer token.",
        "env": ["LINKEDEYE_ALERTMANAGER_WEBHOOK_TOKEN"],
        "details": [("Endpoint", f"POST {am_url}"), ("Bearer token", _token_detail(am)),
                    ("Last alert received", last_alert)],
        "testable": False, "last_test": None,
        "warning": bool(am) and len(am) < 24,
    })

    li = getattr(settings, "LOG_INGEST_TOKEN", "")
    li_url = _reverse("observe:log_ingest") or "/api/v1/logs/"
    last_log = _latest_event(source="observe", kind="log")
    items.append({
        "key": "logs", "name": "Log ingest", "icon": "logs", "configured": bool(li),
        "purpose": "Log shippers (Fluent Bit, Vector, Promtail…) post log lines with this bearer token.",
        "env": ["LINKEDEYE_LOG_INGEST_TOKEN"],
        "details": [("Endpoint", f"POST {li_url}"), ("Bearer token", _token_detail(li)),
                    ("Last log event", last_log)],
        "testable": False, "last_test": None,
        "warning": bool(li) and len(li) < 24,
    })

    st2 = getattr(settings, "STACKSTORM_URL", "")
    items.append({
        "key": "stackstorm", "name": "StackStorm", "icon": "bot", "configured": bool(st2),
        "purpose": "Automation runbooks and event workflows trigger StackStorm webhooks.",
        "env": ["LINKEDEYE_STACKSTORM_URL", "LINKEDEYE_STACKSTORM_API_KEY"],
        "details": [("Webhook URL", safe_url(st2) or "–"),
                    ("API key", "Set" if getattr(settings, "STACKSTORM_API_KEY", "") else "Not set")],
        "testable": True, "test_label": "Ping", "last_test": tests.get("stackstorm"),
    })

    hooks = list(getattr(settings, "NOTIFY_WEBHOOK_URLS", []) or [])
    sev = ", ".join(getattr(settings, "NOTIFY_SEVERITIES", []) or []) or "none"
    items.append({
        "key": "webhooks", "name": "Notification webhooks", "icon": "share", "configured": bool(hooks),
        "purpose": "JSON POST for every critical/warning event (Slack, Teams, Apprise, StackStorm…).",
        "env": ["LINKEDEYE_NOTIFY_WEBHOOK_URLS", "LINKEDEYE_NOTIFY_SEVERITIES"],
        "details": [("Endpoints", f"{len(hooks)} configured" if hooks else "None"),
                    ("Hosts", ", ".join(sorted({url_host(u) for u in hooks})) or "–"),
                    ("Severities", sev)],
        "testable": True, "test_key": "notify", "test_label": "Send test notification",
        "last_test": tests.get("notify"),
    })

    emails = list(getattr(settings, "NOTIFY_EMAILS", []) or [])
    backend = getattr(settings, "EMAIL_BACKEND", "")
    items.append({
        "key": "email", "name": "E-mail notifications", "icon": "mail", "configured": bool(emails),
        "purpose": "E-mail for every critical/warning event.",
        "env": ["LINKEDEYE_NOTIFY_EMAILS", "LINKEDEYE_EMAIL_HOST", "LINKEDEYE_EMAIL_PORT", "LINKEDEYE_EMAIL_HOST_USER",
                "LINKEDEYE_EMAIL_HOST_PASSWORD", "LINKEDEYE_EMAIL_USE_TLS", "LINKEDEYE_DEFAULT_FROM_EMAIL"],
        "details": [("Recipients", f"{len(emails)} address(es)" if emails else "None"),
                    ("Backend", backend.rsplit(".", 2)[-2] if backend.count(".") >= 2 else backend or "–"),
                    ("SMTP server", f"{getattr(settings, 'EMAIL_HOST', '')}:{getattr(settings, 'EMAIL_PORT', '')}"),
                    ("TLS", "On" if getattr(settings, "EMAIL_USE_TLS", False) else "Off"),
                    ("SMTP password", "Set" if getattr(settings, "EMAIL_HOST_PASSWORD", "") else "Not set"),
                    ("From", getattr(settings, "DEFAULT_FROM_EMAIL", "") or "–")],
        "testable": True, "test_key": "notify", "test_label": "Send test notification",
        "last_test": tests.get("notify"),
    })

    nag = str(_setting("NAGIOS_URL") or "").strip()
    items.append({
        "key": "nagios", "name": "Nagios", "icon": "server", "configured": bool(nag),
        "purpose": "Host and service status for Monitoring › Nagios Status (statusjson.cgi).",
        "env": ["LINKEDEYE_NAGIOS_URL", "LINKEDEYE_NAGIOS_USER", "LINKEDEYE_NAGIOS_PASSWORD"],
        "details": [("Server", safe_url(nag) or "–"),
                    ("User", "Set" if _setting("NAGIOS_USER") else "Not set"),
                    ("Password", "Set" if _setting("NAGIOS_PASSWORD") else "Not set")],
        "testable": False, "last_test": None,
    })
    channels = notify_channels()
    for it in items:
        it.setdefault("test_key", it["key"])
        it.setdefault("warning", False)
        it["test_enabled"] = it["testable"] and (channels > 0 if it["test_key"] == "notify" else it["configured"])
    return items


def _record(request, integration, ok, message, started):
    user = getattr(request, "user", None)
    authed = user is not None and user.is_authenticated
    return IntegrationTest.objects.create(
        integration=integration, ok=ok, message=str(message)[:500],
        duration_ms=round((time.monotonic() - started) * 1000, 1),
        tested_by=user if authed else None, tested_by_name=user.get_username() if authed else "system",
    )


def test_prometheus():
    """Instant query `up`. Returns (ok, message)."""
    from core import prometheus
    if not prometheus.configured():
        return False, "Prometheus is not connected (set LINKEDEYE_PROMETHEUS_URL)."
    try:
        rows = prometheus.query("up")
    except prometheus.PrometheusError as e:
        return False, str(e)
    except Exception as e:  # never surface a traceback
        log.exception("prometheus test failed")
        return False, f"Unexpected error: {e.__class__.__name__}"
    up = sum(1 for r in rows if r.get("value") == 1)
    if not rows:
        return True, "Prometheus answered, but the 'up' query returned no targets."
    return True, f"Prometheus answered: {up} of {len(rows)} target(s) up."


def notify_channels():
    return len(getattr(settings, "NOTIFY_WEBHOOK_URLS", []) or []) + (1 if getattr(settings, "NOTIFY_EMAILS", []) else 0)


def test_notify(actor="system"):
    """Send a synthetic warning event through core.notify.deliver. The event is never saved, so it does not show up
    in the event stream or open incidents. Returns (ok, message)."""
    from core.models import Event
    from core.notify import deliver
    channels = notify_channels()
    if not channels:
        return False, "No notification channel is configured (set LINKEDEYE_NOTIFY_WEBHOOK_URLS or LINKEDEYE_NOTIFY_EMAILS)."
    if "warning" not in (getattr(settings, "NOTIFY_SEVERITIES", []) or []):
        return False, "Warning events are not delivered: add 'warning' to LINKEDEYE_NOTIFY_SEVERITIES."
    ev = Event(tenant_key=tenant(), source="administration", kind="test", severity="warning",
               title="LinkedEye test notification",
               message=f"This is a test notification sent by {actor} from Administration › Integrations. No action is needed.",
               occurred_at=timezone.now(), object_type="administration.test", object_id="")
    try:
        sent = deliver(ev)
    except Exception as e:  # deliver() swallows channel errors itself; this is a last resort
        log.exception("test notification failed")
        return False, f"Unexpected error: {e.__class__.__name__}"
    if sent == channels:
        return True, f"Test notification delivered to {sent} of {channels} channel(s)."
    return False, f"Test notification delivered to {sent} of {channels} channel(s); see the server log for failures."


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Do not follow redirects: the API key header must not be forwarded to another host."""

    def redirect_request(self, *args, **kwargs):
        return None


def test_stackstorm():
    """GET the configured StackStorm URL (no redirects, short timeout). Returns (ok, message). Never raises."""
    url = (getattr(settings, "STACKSTORM_URL", "") or "").strip()
    if not url:
        return False, "StackStorm is not configured (set LINKEDEYE_STACKSTORM_URL)."
    p = urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        return False, "LINKEDEYE_STACKSTORM_URL must be an http(s) URL."
    headers = {"Accept": "application/json", "User-Agent": "LinkedEye-Admin/1.0"}
    if getattr(settings, "STACKSTORM_API_KEY", ""):
        headers["St2-Api-Key"] = settings.STACKSTORM_API_KEY
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with opener.open(req, timeout=TEST_TIMEOUT) as r:  # noqa: S310 - operator-configured URL
            return True, f"StackStorm answered HTTP {r.status}."
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return False, f"StackStorm rejected the API key (HTTP {e.code}); check LINKEDEYE_STACKSTORM_API_KEY."
        if e.code in (404, 405):
            return True, f"StackStorm is reachable (HTTP {e.code} for a GET on a webhook URL is expected)."
        if 300 <= e.code < 400:
            return False, f"StackStorm redirected (HTTP {e.code}); set LINKEDEYE_STACKSTORM_URL to the final URL."
        return False, f"StackStorm returned HTTP {e.code}."
    except (urllib.error.URLError, TimeoutError, socket.timeout, OSError) as e:
        return False, f"StackStorm unreachable: {getattr(e, 'reason', e)}"
    except Exception as e:
        log.exception("stackstorm ping failed")
        return False, f"Unexpected error: {e.__class__.__name__}"


TESTS = {"prometheus": test_prometheus, "notify": None, "stackstorm": test_stackstorm}


def run_test(request, key):
    """Run one integration test, store an IntegrationTest row and return it."""
    started = time.monotonic()
    if key == "notify":
        actor = request.user.get_username() if getattr(request, "user", None) and request.user.is_authenticated else "system"
        ok, msg = test_notify(actor)
    else:
        ok, msg = TESTS[key]()
    return _record(request, key, ok, msg, started)


# ------------------------------------------------------------------ system health
def _check(key, label, status, value, detail="", icon="info"):
    return {"key": key, "label": label, "status": status, "value": value, "detail": detail, "icon": icon}


def database_check():
    started = time.monotonic()
    vendor = connection.vendor
    name = settings.DATABASES["default"].get("NAME", "")
    if vendor == "sqlite":
        name = os.path.basename(str(name))
    try:
        with connection.cursor() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()
    except Exception as e:
        return _check("database", "Database", "crit", "Unreachable", f"{vendor}: {e.__class__.__name__}", "database")
    ms = (time.monotonic() - started) * 1000
    return _check("database", "Database", "ok", "Reachable", f"{vendor} · {name} · {ms:.0f} ms", "database")


def pending_migrations():
    """List of (app_label, migration_name) not yet applied, or raises."""
    from django.db.migrations.executor import MigrationExecutor
    executor = MigrationExecutor(connection)
    plan = executor.migration_plan(executor.loader.graph.leaf_nodes())
    return [(m.app_label, m.name) for m, backwards in plan if not backwards]


def migrations_check():
    try:
        pending = pending_migrations()
    except Exception as e:
        return _check("migrations", "Migrations", "crit", "Unknown", f"Could not read migration state: {e.__class__.__name__}", "layers"), []
    if pending:
        apps_ = sorted({a for a, _ in pending})
        return _check("migrations", "Migrations", "warn", f"{len(pending)} pending",
                      "Run manage.py migrate · " + ", ".join(apps_), "layers"), pending
    return _check("migrations", "Migrations", "ok", "Up to date", "All migrations applied", "layers"), []


def _age(dt):
    return None if dt is None else max(0, int((timezone.now() - dt).total_seconds()))


def _fmt_age(seconds):
    if seconds is None:
        return "never"
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60} min ago"
    if seconds < 86400:
        return f"{seconds // 3600} h ago"
    return f"{seconds // 86400} d ago"


def probe_freshness():
    """Latest UrlResult / DomainCheck times. Returns a list of dicts with status ok/warn/mute."""
    from domainmonitor.models import Domain, DomainCheck
    from urlchecker.models import UrlCheck, UrlResult
    t = tenant()
    rows = []
    sources = [
        ("url", "URL checks", UrlCheck.objects.filter(tenant_key=t, enabled=True).count(),
         UrlResult.objects.filter(url_check__tenant_key=t).order_by("-checked_at").values_list("checked_at", flat=True).first()),
        ("domain", "Domain checks", Domain.objects.filter(tenant_key=t, is_active=True, monitor_enabled=True).count(),
         DomainCheck.objects.filter(domain__tenant_key=t).order_by("-checked_at").values_list("checked_at", flat=True).first()),
    ]
    for key, label, enabled, latest in sources:
        age = _age(latest)
        if not enabled:
            status, note = "mute", "Nothing enabled to check"
        elif latest is None:
            status, note = "warn", "No result stored yet — is manage.py run_probes running?"
        elif age > PROBE_STALE_SECONDS:
            status, note = "warn", f"Older than {PROBE_STALE_SECONDS // 60} min — is manage.py run_probes running?"
        else:
            status, note = "ok", "Fresh"
        rows.append({"key": key, "label": label, "enabled": enabled, "latest": latest, "age": age,
                     "age_text": _fmt_age(age), "status": status, "note": note})
    return rows


def scheduler_check():
    hb = Heartbeat.objects.filter(key="scheduler").first()
    if hb is None:
        return _check("scheduler", "Scheduler", "warn", "No heartbeat",
                      "manage.py run_probes has not reported yet (job administration.heartbeat).", "clock"), None
    age = hb.age_seconds
    where = f"{hb.host or 'unknown host'}" + (f" · pid {hb.pid}" if hb.pid else "")
    if age > HEARTBEAT_STALE_SECONDS:
        return _check("scheduler", "Scheduler", "warn", f"Last seen {_fmt_age(age)}",
                      f"run_probes stopped reporting ({where}).", "clock"), hb
    return _check("scheduler", "Scheduler", "ok", "Running", f"Heartbeat {_fmt_age(age)} · {where}", "clock"), hb


def event_counts(hours=24):
    from core.models import Event
    since = timezone.now() - timedelta(hours=hours)
    qs = Event.objects.filter(tenant_key=tenant(), occurred_at__gte=since)
    by_sev = dict(qs.values_list("severity").annotate(n=Count("id")).order_by())
    sev = [{"key": k, "label": label, "count": by_sev.get(k, 0)} for k, label in Event.SEVERITY]
    sources = list(qs.values("source").annotate(n=Count("id")).order_by("-n", "source")[:8])
    return {"severity": sev, "total": sum(by_sev.values()), "sources": sources, "hours": hours}


def _fmt_interval(seconds):
    s = int(seconds)
    if s % 3600 == 0 and s >= 3600:
        return f"every {s // 3600} h"
    if s % 60 == 0 and s >= 60:
        return f"every {s // 60} min"
    return f"every {s} s"


def registered_jobs():
    from core.jobs import JOBS
    out = []
    for name, job in sorted(JOBS.items()):
        func = job.get("func")
        out.append({"name": name, "interval": job.get("interval"), "interval_text": _fmt_interval(job.get("interval") or 0),
                    "func": f"{getattr(func, '__module__', '')}.{getattr(func, '__qualname__', getattr(func, '__name__', ''))}".strip(".")})
    return out


def _db_version():
    try:
        if connection.vendor == "sqlite":
            import sqlite3
            return f"SQLite {sqlite3.sqlite_version}"
        with connection.cursor() as cur:
            if connection.vendor == "postgresql":
                cur.execute("SHOW server_version")
                return f"PostgreSQL {cur.fetchone()[0]}"
            if connection.vendor == "mysql":
                cur.execute("SELECT VERSION()")
                return f"MySQL {cur.fetchone()[0]}"
    except Exception:
        pass
    return connection.vendor


def versions(pending=()):
    """Platform versions plus every local app with its latest applied migration."""
    from django.db.migrations.recorder import MigrationRecorder
    platform_rows = [("LinkedEye", getattr(settings, "LINKEDEYE_VERSION", "–")), ("Django", django.get_version()),
                     ("Python", platform.python_version()), ("Database", _db_version()),
                     ("OS", f"{platform.system()} {platform.release()}"), ("Tenant", tenant())]
    try:
        applied = MigrationRecorder(connection).applied_migrations()
    except Exception:
        applied = {}
    latest = {}
    for app_label, name in applied:
        if app_label not in latest or name > latest[app_label]:
            latest[app_label] = name
    pend = {}
    for app_label, _ in pending:
        pend[app_label] = pend.get(app_label, 0) + 1
    base = str(settings.BASE_DIR)
    rows = []
    for cfg in apps.get_app_configs():
        if not str(cfg.path).startswith(base) or "site-packages" in str(cfg.path):
            continue
        mod = sys.modules.get(cfg.name)
        rows.append({"label": cfg.label, "name": cfg.verbose_name,
                     "version": getattr(mod, "__version__", "") or getattr(settings, "LINKEDEYE_VERSION", ""),
                     "migration": latest.get(cfg.label, ""), "pending": pend.get(cfg.label, 0)})
    return platform_rows, rows


def deployment_checks():
    rows = []
    rows.append(("DEBUG", "warn" if settings.DEBUG else "ok", "On — development only" if settings.DEBUG else "Off"))
    rows.append(("Secret key", "warn" if settings.SECRET_KEY == "dev-only-insecure-key" else "ok",
                 "Development key — set LINKEDEYE_SECRET_KEY" if settings.SECRET_KEY == "dev-only-insecure-key" else "Set"))
    rows.append(("Allowed hosts", "ok" if settings.ALLOWED_HOSTS else "warn", ", ".join(settings.ALLOWED_HOSTS) or "None — set LINKEDEYE_ALLOWED_HOSTS"))
    secure = getattr(settings, "SESSION_COOKIE_SECURE", False) and getattr(settings, "CSRF_COOKIE_SECURE", False)
    rows.append(("Secure cookies", "ok" if secure else "warn", "On" if secure else "Off (HTTPS cookies disabled)"))
    return rows


STATUS_RANK = {"ok": 0, "mute": 0, "warn": 1, "crit": 2}


def health():
    db = database_check()
    mig, pending = migrations_check()
    sched, hb = scheduler_check()
    probes = probe_freshness()
    probe_status = max((p["status"] for p in probes), key=lambda s: STATUS_RANK[s], default="mute")
    probe_card = _check("probes", "Probe results", probe_status,
                        "Fresh" if probe_status == "ok" else ("Stale" if probe_status == "warn" else "Idle"),
                        " · ".join(f"{p['label']}: {p['age_text']}" for p in probes), "radar")
    checks = [db, mig, sched, probe_card]
    overall = max((c["status"] for c in checks), key=lambda s: STATUS_RANK[s])
    platform_rows, app_rows = versions(pending)
    return {"checks": checks, "overall": overall, "pending": pending, "heartbeat": hb, "probes": probes,
            "events": event_counts(24), "jobs": registered_jobs(), "platform": platform_rows, "apps": app_rows,
            "deployment": deployment_checks(), "stale_minutes": PROBE_STALE_SECONDS // 60}


def health_summary():
    """Cheap overall status for the index card (no migration graph walk when the database is down)."""
    db = database_check()
    if db["status"] == "crit":
        return "crit"
    sched, _ = scheduler_check()
    statuses = [db["status"], sched["status"]] + [p["status"] for p in probe_freshness()]
    try:
        if pending_migrations():
            statuses.append("warn")
    except Exception:
        statuses.append("crit")
    return max(statuses, key=lambda s: STATUS_RANK[s])


# ------------------------------------------------------------------ sites
def site_usage():
    """{site name: {"urls": n, "domains": n}} for the tenant."""
    from domainmonitor.models import Domain
    from urlchecker.models import UrlCheck
    t = tenant()
    usage = {}
    for name, n in UrlCheck.objects.filter(tenant_key=t).values_list("site").annotate(n=Count("id")).order_by():
        usage.setdefault(name, {"urls": 0, "domains": 0})["urls"] = n
    for name, n in Domain.objects.filter(tenant_key=t).values_list("site_key").annotate(n=Count("id")).order_by():
        usage.setdefault(name, {"urls": 0, "domains": 0})["domains"] = n
    return usage


def unmapped_site_names():
    """Site names used by URL checks / domains that have no core.Site record yet."""
    from core.models import Site
    known = set(Site.objects.filter(tenant_key=tenant()).values_list("name", flat=True))
    return sorted(n for n in site_usage() if n and n != "All Sites" and n not in known)


def bootstrap_sites():
    """Run the core `bootstrap_sites` command. Returns (created names, command output)."""
    from django.core.management import call_command

    from core.models import Site
    before = set(Site.objects.filter(tenant_key=tenant()).values_list("name", flat=True))
    out = io.StringIO()
    call_command("bootstrap_sites", stdout=out)
    after = set(Site.objects.filter(tenant_key=tenant()).values_list("name", flat=True))
    return sorted(after - before), out.getvalue().strip()
