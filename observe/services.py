"""Exporter health checks, log ingest and the queries behind the observe pages."""
import hashlib
import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone

from django.conf import settings
from django.db import close_old_connections
from django.db.models import Count, Q
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from core.access import PERMS, RANK, _memberships, can, scope_by_site
from core.events import emit
from core.models import Event

from . import scrape
from .models import LEVEL_ALIASES, Exporter, ExporterStatus, LogEntry

log = logging.getLogger("linkedeye.observe")

# ---------------------------------------------------------------- limits
MAX_ENTRIES = 1000
MAX_BYTES = 1024 * 1024
MAX_MESSAGE = 8000
MAX_EVENTS_PER_BATCH = 25
EVENT_WINDOW = timedelta(minutes=10)
CHECK_ALL_LIMIT = 200

INFO_LEVELS = ("DEBUG", "INFO")
WARN_LEVELS = ("WARN",)
ERROR_LEVELS = ("ERROR", "CRITICAL")


def tenant():
    return settings.LINKEDEYE_TENANT


# ---------------------------------------------------------------- access
def _tenant_wide(user, perm):
    if user.is_superuser:
        return True
    ms = _memberships(user)
    if not ms:
        return can(user, perm)
    return any(m.site is None and RANK[m.role] >= PERMS[perm] for m in ms)


def can_manage(user, perm, site):
    """`perm` on a record's site. Records without a site (or "All Sites") need a tenant-wide role."""
    if site and site != "All Sites":
        return can(user, perm, site_name=site)
    return can(user, perm) and _tenant_wide(user, perm)


def exporters_for(user):
    return scope_by_site(Exporter.objects.filter(tenant_key=tenant()), user)


def logs_for(user):
    return scope_by_site(LogEntry.objects.filter(tenant_key=tenant()), user)


def events_for(user):
    return scope_by_site(Event.objects.filter(tenant_key=tenant()), user)


def site_names(*extra_querysets):
    """Site names from core.Site plus values already used by records."""
    from core.models import Site
    names = set(Site.objects.filter(tenant_key=tenant()).values_list("name", flat=True))
    for qs in extra_querysets:
        names |= set(qs.order_by().values_list("site", flat=True).distinct())
    names.discard("")
    return sorted(names, key=str.lower)


# ---------------------------------------------------------------- exporter health
def _apply_result(exp, res, now):
    """Store a scrape result on the exporter and emit an event on active<->error. Returns the new status."""
    before = exp.status
    exp.last_checked_at = now
    exp.last_scrape_ms = res.response_ms
    if res.ok:
        exp.set_status(ExporterStatus.ACTIVE, now)
        exp.last_seen = now
        exp.samples = res.samples
        exp.last_error = "Response truncated at 16 MB; samples counted up to there" if res.truncated else ""
    else:
        exp.set_status(ExporterStatus.ERROR, now)
        exp.last_error = (res.error or "Scrape failed")[:500]
    exp.save(update_fields=["status", "status_changed_at", "last_checked_at", "last_seen", "last_scrape_ms",
                            "samples", "last_error", "updated_at"])
    fp = f"exporter:{exp.pk}"
    if exp.status == ExporterStatus.ERROR and before != ExporterStatus.ERROR:
        emit(source="observe", title=f"Exporter {exp.name} is failing", severity="warning",
             message=f"Scraping {exp.metrics_url} failed: {exp.last_error}", site=exp.site, obj=exp,
             fingerprint=fp, exporter=exp.name, category=exp.category, previous=before, error=exp.last_error)
    elif exp.status == ExporterStatus.ACTIVE and before == ExporterStatus.ERROR:
        emit(source="observe", title=f"Exporter {exp.name} recovered", severity="ok",
             message=f"{exp.metrics_url} answered with {exp.samples} samples in {exp.last_scrape_ms:g} ms.",
             site=exp.site, obj=exp, fingerprint=fp, exporter=exp.name, category=exp.category, previous=before,
             samples=exp.samples)
    return exp.status


def _scrape_one(exp):
    try:
        return scrape.scrape(exp.metrics_url)
    except Exception as e:  # never let one exporter break the batch
        log.exception("scrape of %s failed", exp.metrics_url)
        return scrape.ScrapeResult(error=f"{type(e).__name__}: {e}")


def _scrape_in_worker(exp):
    try:
        return _scrape_one(exp)
    finally:
        close_old_connections()   # pool threads must not leak DB connections


def check_exporters(exporters):
    """Scrape the given exporters in parallel and store the results. Returns [(exporter, ScrapeResult)]."""
    todo = [e for e in exporters if e.scrapeable]
    if not todo:
        return []
    workers = max(1, min(getattr(settings, "PROBE_WORKERS", 8), len(todo)))
    if workers == 1:
        results = [_scrape_one(e) for e in todo]
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(_scrape_in_worker, todo))
    now = timezone.now()
    for exp, res in zip(todo, results):
        _apply_result(exp, res, now)
    return list(zip(todo, results))


def sync_config_states():
    """Exporters that cannot be scraped show their configuration state (inactive / not configured)."""
    qs = Exporter.objects.all()
    n = qs.filter(enabled=False).exclude(status=ExporterStatus.INACTIVE).update(
        status=ExporterStatus.INACTIVE, status_changed_at=timezone.now(), last_error="")
    n += qs.filter(enabled=True, metrics_url="").exclude(status=ExporterStatus.NOT_CONFIGURED).update(
        status=ExporterStatus.NOT_CONFIGURED, status_changed_at=timezone.now(), last_error="No metrics URL configured")
    return n


# ---------------------------------------------------------------- log ingest
class IngestError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def parse_payload(body, content_type=""):
    """JSON array (or a single object) or NDJSON -> list of dicts."""
    if len(body) > MAX_BYTES:
        raise IngestError(f"Request body exceeds {MAX_BYTES // 1024} KB", 413)
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        raise IngestError("Body must be UTF-8")
    stripped = text.strip()
    if not stripped:
        raise IngestError("Empty body")
    ndjson = "ndjson" in content_type or "jsonl" in content_type or "json-seq" in content_type
    if not ndjson and stripped[0] in "[{":
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError:
            data = None
            if stripped[0] != "{":
                raise IngestError("Invalid JSON array")
        if isinstance(data, dict):
            data = [data]
        if data is not None:
            if not isinstance(data, list):
                raise IngestError("Expected a JSON array of log entries")
            if len(data) > MAX_ENTRIES:
                raise IngestError(f"Too many entries: {len(data)} (max {MAX_ENTRIES} per request)", 413)
            return data
    entries = []
    for no, line in enumerate(stripped.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        if len(entries) >= MAX_ENTRIES:
            raise IngestError(f"Too many entries (max {MAX_ENTRIES} per request)", 413)
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError as e:
            raise IngestError(f"Line {no} is not valid JSON: {e.msg}")
    return entries


def _parse_ts(value, now):
    if value in (None, ""):
        return now
    if isinstance(value, bool):
        raise ValueError("ts must be an ISO 8601 string or a Unix timestamp")
    if isinstance(value, (int, float)):
        v = float(value)
        if v > 1e14:      # microseconds
            v /= 1e6
        elif v > 1e11:    # milliseconds
            v /= 1e3
        ts = datetime.fromtimestamp(v, tz=dt_timezone.utc)
    elif isinstance(value, str):
        ts = parse_datetime(value.strip().replace(" ", "T", 1) if "T" not in value else value.strip())
        if ts is None:
            raise ValueError("ts is not an ISO 8601 date-time")
        if timezone.is_naive(ts):
            ts = timezone.make_aware(ts, dt_timezone.utc)
    else:
        raise ValueError("ts must be an ISO 8601 string or a Unix timestamp")
    if ts > now + timedelta(days=1):
        raise ValueError("ts is more than a day in the future")
    if ts.year < 2000:
        raise ValueError("ts is before the year 2000")
    return ts


def _text(entry, key, maxlen, required=False):
    v = entry.get(key)
    if v is None or (isinstance(v, str) and not v.strip()):
        if required:
            raise ValueError(f"'{key}' is required")
        return ""
    if not isinstance(v, (str, int, float)) or isinstance(v, bool):
        raise ValueError(f"'{key}' must be a string")
    return str(v).strip()[:maxlen]


def validate_entry(entry, now):
    if not isinstance(entry, dict):
        raise ValueError("entry must be a JSON object")
    level_raw = _text(entry, "level", 20, required=True).upper()
    level = LEVEL_ALIASES.get(level_raw)
    if not level:
        raise ValueError(f"unknown level '{level_raw}' (use DEBUG, INFO, WARN, ERROR or CRITICAL)")
    message = entry.get("message")
    if message is None or (isinstance(message, str) and not message.strip()):
        raise ValueError("'message' is required")
    if not isinstance(message, str):
        message = json.dumps(message, default=str) if isinstance(message, (dict, list)) else str(message)
    attributes = entry.get("attributes") or {}
    if not isinstance(attributes, dict):
        raise ValueError("'attributes' must be a JSON object")
    if len(json.dumps(attributes, default=str)) > 16000:
        raise ValueError("'attributes' is larger than 16 KB")
    return LogEntry(
        tenant_key=tenant(), ts=_parse_ts(entry.get("ts", entry.get("timestamp")), now),
        source=_text(entry, "source", 120, required=True), level=level, message=message.strip()[:MAX_MESSAGE],
        host=_text(entry, "host", 255), site=_text(entry, "site", 100), attributes=attributes, received_at=now,
    )


_PATTERNS = [
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "<uuid>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b"), "<ip>"),
    (re.compile(r"\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", re.I), "<mac>"),
    (re.compile(r"\b0x[0-9a-f]+\b|\b[0-9a-f]{12,}\b", re.I), "<hex>"),
    (re.compile(r"\"[^\"]*\"|'[^']*'"), "<str>"),
    (re.compile(r"\d+(?:\.\d+)?"), "<n>"),
    (re.compile(r"\s+"), " "),
]


def message_pattern(message):
    """Collapse variable parts (numbers, IPs, ids, quoted values) so repeats of one problem share a pattern."""
    p = message[:500]
    for rx, repl in _PATTERNS:
        p = rx.sub(repl, p)
    return p.strip().lower()


def log_fingerprint(source, message):
    digest = hashlib.sha1(f"{source.lower()}|{message_pattern(message)}".encode()).hexdigest()[:20]
    return f"observe:log:{digest}"


def _emit_log_events(entries, now):
    """One event per new source+message pattern in the last 10 minutes; capped per batch."""
    emitted = suppressed = 0
    seen = set()
    for e in entries:
        if e.level not in ERROR_LEVELS:
            continue
        fp = log_fingerprint(e.source, e.message)
        if fp in seen:
            suppressed += 1
            continue
        seen.add(fp)
        if Event.objects.filter(fingerprint=fp, occurred_at__gte=now - EVENT_WINDOW).exists():
            suppressed += 1
            continue
        if emitted >= MAX_EVENTS_PER_BATCH:
            suppressed += 1
            continue
        first_line = e.message.splitlines()[0] if e.message else ""
        emit(source="observe", kind="log", title=f"{e.level} in {e.source}: {first_line[:140]}",
             severity="critical" if e.level == "CRITICAL" else "warning", message=e.message[:2000], site=e.site,
             obj=e, fingerprint=fp, log_source=e.source, level=e.level, host=e.host,
             pattern=message_pattern(e.message)[:200])
        emitted += 1
    return emitted, suppressed


def ingest(raw_entries, now=None):
    """Validate and store entries. Returns a summary dict (accepted/rejected/errors/events)."""
    now = now or timezone.now()
    good, errors = [], []
    for i, raw in enumerate(raw_entries):
        try:
            good.append(validate_entry(raw, now))
        except (ValueError, OverflowError, OSError) as e:
            errors.append({"index": i, "error": str(e)})
    if good:
        good = LogEntry.objects.bulk_create(good, batch_size=500)
        if any(e.pk is None for e in good if e.level in ERROR_LEVELS):
            # backends without RETURNING: re-read so events can point at the stored rows
            good = list(LogEntry.objects.filter(tenant_key=tenant(), received_at=now).order_by("id"))
    emitted, suppressed = _emit_log_events(good, now)
    return {"accepted": len(good), "rejected": len(errors), "errors": errors[:20],
            "events": emitted, "events_suppressed": suppressed}


def prune_logs(days=None, batch=5000):
    days = getattr(settings, "LOG_RETENTION_DAYS", 14) if days is None else days
    cutoff = timezone.now() - timedelta(days=days)
    total = 0
    while True:
        ids = list(LogEntry.objects.filter(ts__lt=cutoff).values_list("id", flat=True)[:batch])
        if not ids:
            break
        total += LogEntry.objects.filter(id__in=ids).delete()[0]
        if len(ids) < batch:
            break
    return total


# ---------------------------------------------------------------- page data
RANGES = [("15m", "Last 15 minutes", timedelta(minutes=15)), ("1h", "Last 1 hour", timedelta(hours=1)),
          ("6h", "Last 6 hours", timedelta(hours=6)), ("24h", "Last 24 hours", timedelta(hours=24)),
          ("7d", "Last 7 days", timedelta(days=7)), ("30d", "Last 30 days", timedelta(days=30)),
          ("all", "All time", None)]
RANGE_MAP = {k: d for k, _, d in RANGES}


def since_for(range_key, default="24h", now=None):
    now = now or timezone.now()
    key = range_key if range_key in RANGE_MAP else default
    delta = RANGE_MAP[key]
    return key, (now - delta if delta else None)


def logs_trend(qs, now=None, hours=24):
    """Hourly stacked counts (Info / Warn / Error) over the last `hours`, aligned to local hours, in one query."""
    now = timezone.localtime(now or timezone.now())
    end = now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
    starts = [end - timedelta(hours=hours - i) for i in range(hours)]
    groups = {"i": INFO_LEVELS, "w": WARN_LEVELS, "e": ERROR_LEVELS}
    aggs = {}
    for idx, s in enumerate(starts):
        win = Q(ts__gte=s, ts__lt=s + timedelta(hours=1))
        for g, levels in groups.items():
            aggs[f"{g}{idx}"] = Count("id", filter=win & Q(level__in=levels))
    row = qs.filter(ts__gte=starts[0], ts__lt=end).aggregate(**aggs)
    series = {g: [row[f"{g}{i}"] or 0 for i in range(hours)] for g in groups}
    labels = [f"{s:%H}:00" for s in starts]
    peak = max((series["i"][i] + series["w"][i] + series["e"][i] for i in range(hours)), default=0)
    extra = {"yMax": 4} if peak < 4 else {}   # whole-number ticks for tiny volumes
    return {**extra, "labels": labels, "tipLabels": [f"{s:%d %b %H}:00–{(s + timedelta(hours=1)):%H}:00" for s in starts],
            "unit": "", "xLabelEvery": 4, "yTicks": 4, "total": sum(sum(v) for v in series.values()), "peak": peak,
            "series": [{"name": "Info", "color": "#1565f0", "values": series["i"]},
                       {"name": "Warn", "color": "#f59e0b", "values": series["w"]},
                       {"name": "Error", "color": "#dc2626", "values": series["e"]}]}


def change_pct(now_value, before_value):
    if now_value is None or not before_value:
        return None
    return round(100.0 * (now_value - before_value) / before_value)


def log_row(e):
    local = timezone.localtime(e.ts)
    return {"id": e.pk, "ts": e.ts.isoformat(), "time": f"{local:%H:%M:%S}", "date": f"{local:%d %b}",
            "source": e.source, "level": e.level, "tone": e.tone, "message": e.message[:1000], "host": e.host,
            "site": e.site}
