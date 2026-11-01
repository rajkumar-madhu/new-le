"""BOD / EOD validation engine: trading calendar, reference lookups, runs, sign-offs and the scheduler job.

Market hours (IST): BOD 07:00–09:00, trading 09:00–15:30, EOD 15:30–16:00.
Other modules are reached lazily through `apps.get_model` so this app keeps working when one is absent.
"""
import csv
import io
import logging
from dataclasses import dataclass, field
from datetime import date, datetime, time, timedelta
from zoneinfo import ZoneInfo

from django.apps import apps
from django.conf import settings
from django.db import DatabaseError, IntegrityError, transaction
from django.urls import NoReverseMatch, reverse
from django.utils import timezone

from core.access import can
from core.events import emit

from .models import GLOBAL_SITES, ChecklistItem, Holiday, Mode, Run, RunItem

log = logging.getLogger("linkedeye.bodeod")

IST = ZoneInfo("Asia/Kolkata")
TRADING_EXCHANGES = ("ALL", "NSE")      # holidays that close the market for this console
PHASES = [  # (key, label, start, end) in IST
    ("bod", "BOD window", time(7, 0), time(9, 0)),
    ("trading", "Trading hours", time(9, 0), time(15, 30)),
    ("eod", "EOD window", time(15, 30), time(16, 0)),
]
STALE_RUN_MINUTES = 30
LATE_START_GRACE_MINUTES = 60
STATUS_LABELS = dict(RunItem.STATUSES)
RUN_SEVERITY = {"fail": "critical", "warn": "warning", "pass": "ok"}
MAX_CSV_BYTES = 512 * 1024
MAX_CSV_ROWS = 2000


def tenant():
    return settings.LINKEDEYE_TENANT


def now_ist(now=None):
    return timezone.localtime(now or timezone.now(), IST)


def today_ist(now=None):
    return now_ist(now).date()


def modes_qs():
    return Mode.objects.filter(tenant_key=tenant())


def user_can(user, perm, site=""):
    """Permission on a mode/site: global records use the user's best role, site records that site's role."""
    if site in GLOBAL_SITES:
        return can(user, perm)
    return can(user, perm, site)


# ------------------------------------------------------------------ trading calendar
def holidays_on(day, exchanges=TRADING_EXCHANGES):
    return list(Holiday.objects.filter(tenant_key=tenant(), date=day, exchange__in=exchanges))


def trading_day(day):
    """(is_trading_day, reason). Weekends and ALL/NSE holidays close the market."""
    if day.weekday() >= 5:
        return False, f"Weekend ({day:%A})"
    hs = holidays_on(day)
    if hs:
        return False, "Holiday: " + "; ".join(f"{h.description} ({h.exchange})" for h in hs)
    return True, "Trading day"


def next_trading_day(day, limit=30):
    d = day + timedelta(days=1)
    closed = set(Holiday.objects.filter(tenant_key=tenant(), exchange__in=TRADING_EXCHANGES,
                                        date__gte=d, date__lte=d + timedelta(days=limit)).values_list("date", flat=True))
    for _ in range(limit):
        if d.weekday() < 5 and d not in closed:
            return d
        d += timedelta(days=1)
    return None


def market_phase(now=None):
    """Current market phase dict {key, label, start, end} (key 'closed' outside the windows)."""
    t = now_ist(now).time()
    for key, label, start, end in PHASES:
        if start <= t < end:
            return {"key": key, "label": label, "start": start, "end": end}
    return {"key": "closed", "label": "Market closed", "start": None, "end": None}


def window_state(mode, now=None, trading=None):
    """'open' | 'upcoming' | 'closed' for the mode's window today (IST); 'no_trading' on weekends and holidays."""
    n = now_ist(now)
    if trading is None:
        trading = trading_day(n.date())[0]
    if not trading:
        return "no_trading"
    t = n.time()
    if mode.window_start <= t < mode.window_end:
        return "open"
    if t < mode.window_start:
        return "upcoming"
    return "closed"


def trading_banner(now=None):
    n = now_ist(now)
    is_open, reason = trading_day(n.date())
    hs = holidays_on(n.date(), exchanges=("ALL", "NSE", "BSE", "MCX"))
    return {"now": n, "date": n.date(), "trading": is_open, "reason": reason, "phase": market_phase(now),
            "holidays": hs, "weekend": n.weekday() >= 5, "next_trading": None if is_open else next_trading_day(n.date())}


# ------------------------------------------------------------------ reference lookups
def _model(app_label, name):
    try:
        return apps.get_model(app_label, name)
    except (LookupError, ValueError):
        return None


REF_MODELS = {"url_check": ("urlchecker", "UrlCheck", "name"), "domain": ("domainmonitor", "Domain", "hostname"),
              "tcp_check": ("tcpcheck", "TcpCheck", "name")}


def _ref_url(kind, obj):
    try:
        if kind == "url_check":
            return reverse("urlchecker:detail", args=[obj.pk])
        if kind == "tcp_check":
            return reverse("tcpcheck:detail", args=[obj.pk])
        if kind == "domain":
            return reverse("domains:list") + f"?selected={obj.pk}"
    except NoReverseMatch:
        return ""
    return ""


def query_refs(M, field_name, names=None):
    """{name: obj} for the tenant's records of model M (all of them when names is None, capped at 500).
    Returns None when the model's table is not available."""
    try:
        with transaction.atomic():  # savepoint: a missing table must not poison an outer transaction
            qs = M.objects.all()
            if names is not None:
                qs = qs.filter(**{f"{field_name}__in": list(names)})
            if any(f.name == "tenant_key" for f in M._meta.get_fields()):
                qs = qs.filter(tenant_key=tenant())
            return {getattr(o, field_name): o for o in qs.order_by(field_name)[:500]}
    except DatabaseError:
        log.warning("bodeod: %s is not available (missing table?)", M._meta.label)
        return None


class Resolver:
    """Looks up referenced checks by name in one query per kind (lazy, cached)."""

    def __init__(self, items=()):
        self._cache = {}
        self._wanted = {}
        self._broken = set()
        for it in items:
            if it.kind in REF_MODELS and it.ref_name:
                self._wanted.setdefault(it.kind, set()).add(it.ref_name.strip())

    def available(self, kind):
        if kind == "manual":
            return True
        if kind not in REF_MODELS or _model(*REF_MODELS[kind][:2]) is None:
            return False
        self._load(kind)
        return kind not in self._broken

    def _load(self, kind):
        if kind in self._cache:
            return self._cache[kind]
        app_label, model_name, field_name = REF_MODELS[kind]
        M = _model(app_label, model_name)
        found = {}
        if M is not None:
            names = self._wanted.get(kind, set())
            if names:
                found = query_refs(M, field_name, names)
                if found is None:  # table missing (module installed but not migrated)
                    self._broken.add(kind)
                    found = {}
        self._cache[kind] = found
        return found

    def get(self, kind, ref_name):
        if kind not in REF_MODELS or not ref_name:
            return None
        ref_name = ref_name.strip()
        if ref_name not in self._wanted.get(kind, set()):
            self._wanted.setdefault(kind, set()).add(ref_name)
            self._cache.pop(kind, None)
        return self._load(kind).get(ref_name)

    def link(self, kind, ref_name):
        obj = self.get(kind, ref_name)
        return _ref_url(kind, obj) if obj is not None else ""


def _when(dt):
    return timezone.localtime(dt, IST).strftime("%d %b %H:%M IST") if dt else "never"


def status_of(kind, obj):
    """Map a referenced check to (status, detail). obj=None means the reference is missing."""
    if kind == "domain":
        if obj is None:
            return "unknown", "Domain not found in Domain Monitor"
        if not obj.is_active:
            return "unknown", "Domain is inactive"
        if obj.last_checked_at is None or obj.status == "unknown":
            return "unknown", "Domain has not been checked yet"
        when = _when(obj.last_checked_at)
        if obj.status == "down" or obj.dns_status == "Failed":
            return "critical", f"Down: {obj.last_error or 'not reachable'} (checked {when})"
        if obj.ssl_status in ("Expired", "Invalid"):
            return "critical", f"SSL certificate {obj.ssl_status.lower()} (checked {when})"
        if obj.ssl_status == "Expiring":
            days = obj.ssl_days_left
            return "warning", f"Up; SSL expiring{f' in {days} days' if days is not None else ''} (checked {when})"
        return "ok", f"Up, DNS resolved, SSL {obj.ssl_status.lower()} (checked {when})"

    label = "URL check" if kind == "url_check" else "TCP check"
    if obj is None:
        return "unknown", f"{label} not found"
    if not obj.enabled:
        return "unknown", f"{label} is disabled"
    st = obj.last_status
    if obj.last_checked_at is None or st == "unknown":
        return "unknown", f"{label} has not run yet"
    when = _when(obj.last_checked_at)
    ms = f"{obj.last_response_ms:.0f} ms, " if obj.last_response_ms is not None else ""
    if st == "online":
        return "ok", f"Online ({ms}checked {when})"
    if st == "degraded":
        return "warning", f"Degraded: {obj.last_error or 'slow response'} ({ms}checked {when})"
    if st == "down":
        return "critical", f"Down: {obj.last_error or 'not reachable'} (checked {when})"
    return "unknown", f"Status {st} (checked {when})"


def live_status(item, resolver=None):
    """Current status of a checklist item from its referenced check's latest stored result (no network)."""
    if item.kind == "manual":
        return "pending", "Manual check: needs an operator sign-off"
    resolver = resolver or Resolver([item])
    if not resolver.available(item.kind):
        return "unknown", f"{item.get_kind_display()} module is not available"
    if not item.ref_name:
        return "unknown", "No reference configured"
    return status_of(item.kind, resolver.get(item.kind, item.ref_name))


def refresh_references(items, resolver):
    """Re-run every referenced check once, in parallel per kind. Errors are logged, never raised."""
    batches = {"url_check": [], "domain": [], "tcp_check": []}
    for it in items:
        obj = resolver.get(it.kind, it.ref_name) if it.kind in batches else None
        if obj is None:
            continue
        active = obj.is_active and obj.monitor_enabled if it.kind == "domain" else obj.enabled
        if active and obj not in batches[it.kind]:
            batches[it.kind].append(obj)
    ran = 0
    if batches["url_check"] or batches["domain"]:
        try:
            from probes import runner
            if batches["url_check"]:
                runner.run_url_checks(batches["url_check"])
                ran += len(batches["url_check"])
            if batches["domain"]:
                runner.run_domain_checks(batches["domain"])
                ran += len(batches["domain"])
        except Exception:
            log.exception("bodeod: re-running URL/domain checks failed")
    if batches["tcp_check"]:
        try:
            from tcpcheck import services as tcp_services
            tcp_services.run_checks(batches["tcp_check"])
            ran += len(batches["tcp_check"])
        except ImportError:
            log.info("bodeod: tcpcheck module not available; using stored TCP results")
        except Exception:
            log.exception("bodeod: re-running TCP checks failed")
    return ran


# ------------------------------------------------------------------ run status
def compute_status(results):
    """fail if a critical item is critical; warn if anything is warning/unknown/pending (or a non-critical item is
    critical); otherwise pass."""
    results = list(results)
    if any(r.status == "critical" and r.critical for r in results):
        return "fail"
    if any(r.status in ("warning", "unknown", "pending", "critical") for r in results):
        return "warn"
    return "pass"


def counts(results):
    c = {k: 0 for k in ("ok", "warning", "critical", "unknown", "pending", "signed_off")}
    for r in results:
        c[r.status] = c.get(r.status, 0) + 1
    c["total"] = sum(v for k, v in c.items() if k != "total")
    c["done"] = c["ok"] + c["signed_off"]
    return c


def summarize(results):
    c = counts(results)
    parts = [f"{c['done']}/{c['total']} OK"]
    for key, word in (("critical", "critical"), ("warning", "warning"), ("unknown", "unknown"), ("pending", "pending sign-off")):
        if c[key]:
            parts.append(f"{c[key]} {word}")
    return ", ".join(parts)


def _emit_run(run, previous=None):
    sev = RUN_SEVERITY.get(run.status)
    if not sev:
        return None
    label = dict(Run.STATUSES)[run.status]
    verb = {"pass": "passed", "warn": "completed with warnings", "fail": "failed"}[run.status]
    title = f"{run.mode.code} validation {verb} ({run.trading_date:%d %b %Y})"
    return emit("bodeod", title, severity=sev, message=run.summary, site=run.mode.site,
                obj=run, fingerprint=f"bodeod:mode:{run.mode_id}", mode=run.mode.code, run=run.pk,
                trading_date=run.trading_date.isoformat(), status=run.status, status_label=label,
                previous=previous or "", trigger=run.trigger)


def finalize(run, previous=None, emit_event=True):
    results = list(run.results.all())
    for r in results:  # an automated item never left pending once the run finished
        if r.status == "pending" and r.automated:
            r.status, r.detail = "unknown", r.detail or "Not evaluated"
            r.save(update_fields=["status", "detail"])
    run.status = compute_status(results)
    run.summary = summarize(results)[:300]
    run.finished_at = run.finished_at or timezone.now()
    run.save(update_fields=["status", "summary", "finished_at"])
    if emit_event and run.status != previous:
        _emit_run(run, previous)
    return run


# ------------------------------------------------------------------ runs
class RunError(Exception):
    pass


def latest_run(mode):
    return mode.runs.order_by("-started_at", "-pk").first()


def is_open_for_signoff(run, now=None):
    """Sign-offs are accepted on the latest finished run of a mode for today's trading date."""
    if run.status == "running" or run.trading_date != today_ist(now):
        return False
    latest = latest_run(run.mode)
    return latest is not None and latest.pk == run.pk


def _carry_forward(mode, trading_date):
    """Manual sign-offs given earlier for the same mode and trading date, by checklist item id."""
    out = {}
    qs = RunItem.objects.filter(run__mode=mode, run__trading_date=trading_date, status="signed_off",
                                item__isnull=False).order_by("signed_off_at")
    for ri in qs:
        out[ri.item_id] = ri
    return out


def start_run(mode, user=None, trigger="manual", refresh=None, trading_date=None, now=None):
    """Create and evaluate a run synchronously. Returns the finished Run. Raises RunError on refusal."""
    now = now or timezone.now()
    trading_date = trading_date or today_ist(now)
    refresh = mode.refresh_checks if refresh is None else refresh
    busy = mode.runs.filter(status="running", started_at__gte=now - timedelta(minutes=STALE_RUN_MINUTES)).first()
    if busy:
        raise RunError(f"{mode.code} run #{busy.pk} is still running.")
    items = list(mode.items.filter(enabled=True).order_by("order", "pk"))
    name = ""
    if user is not None and getattr(user, "is_authenticated", False):
        name = user.get_username()
    with transaction.atomic():
        run = Run.objects.create(mode=mode, trading_date=trading_date, started_at=now, trigger=trigger,
                                 triggered_by=user if name else None, triggered_by_name=name or ("scheduler" if trigger == "scheduler" else ""),
                                 refreshed=bool(refresh))
        RunItem.objects.bulk_create([
            RunItem(run=run, item=it, order=it.order, name=it.name, kind=it.kind, ref_name=it.ref_name,
                    critical=it.critical, status="pending") for it in items])
    try:
        evaluate(run, refresh=refresh)
    except Exception:
        log.exception("bodeod: evaluating run %s failed", run.pk)
    return finalize(run)


def evaluate(run, refresh=False):
    """(Re-)evaluate the automated items of a run; manual items keep their sign-off."""
    results = list(run.results.select_related("item"))
    resolver = Resolver(results)
    automated = [r for r in results if r.automated]
    if refresh and automated:
        refresh_references(automated, resolver)
        resolver = Resolver(results)  # reload fresh statuses
    carried = _carry_forward(run.mode, run.trading_date)
    now = timezone.now()
    for r in results:
        if r.automated:
            if not resolver.available(r.kind):
                r.status, r.detail = "unknown", f"{r.get_kind_display()} module is not available"
            elif not r.ref_name:
                r.status, r.detail = "unknown", "No reference configured"
            else:
                r.status, r.detail = status_of(r.kind, resolver.get(r.kind, r.ref_name))
            r.detail = r.detail[:500]
            r.checked_at = now
            r.save(update_fields=["status", "detail", "checked_at"])
        elif r.status == "pending":
            prev = carried.get(r.item_id)
            if prev is not None and prev.run_id != run.pk:
                r.status = "signed_off"
                r.signed_off_by_id, r.signed_off_by_name = prev.signed_off_by_id, prev.signed_off_by_name
                r.signed_off_at, r.note = prev.signed_off_at, prev.note
                r.detail = f"Signed off earlier today (run #{prev.run_id})"
                r.checked_at = now
            else:
                r.detail = "Awaiting operator sign-off"
            r.save()
    return results


def revalidate(run, refresh=True):
    """Re-check the automated items of a finished run (sign-offs are kept)."""
    if run.status == "running":
        raise RunError("The run is still running.")
    previous = run.status
    evaluate(run, refresh=refresh)
    run.finished_at = timezone.now()
    run.refreshed = run.refreshed or refresh
    run.save(update_fields=["finished_at", "refreshed"])
    return finalize(run, previous=previous)


def sign_off(result, user, note):
    """Operator sign-off of a pending manual item. Returns the run (status recomputed)."""
    note = (note or "").strip()
    if result.automated:
        raise RunError("Only manual items need a sign-off.")
    if result.status == "signed_off":
        raise RunError("This item is already signed off.")
    if not note:
        raise RunError("Add a note describing what you verified.")
    run = result.run
    if not is_open_for_signoff(run):
        raise RunError("Sign-offs are only accepted on the latest run for today's trading date.")
    previous = run.status
    result.status = "signed_off"
    result.signed_off_by = user
    result.signed_off_by_name = user.get_username()
    result.signed_off_at = timezone.now()
    result.note = note[:500]
    result.detail = "Signed off"
    result.checked_at = result.signed_off_at
    result.save()
    finalize(run, previous=previous)
    return run


def finalize_stale(now=None):
    """Runs left 'running' (e.g. the process died) are closed with what they have."""
    now = now or timezone.now()
    n = 0
    for run in Run.objects.filter(mode__tenant_key=tenant(), status="running",
                                  started_at__lt=now - timedelta(minutes=STALE_RUN_MINUTES)).select_related("mode"):
        finalize(run, previous="running")
        n += 1
    return n


# ------------------------------------------------------------------ scheduler
def due_modes(now=None):
    """Enabled modes whose auto-run time has come today and that have no scheduled run yet."""
    n = now_ist(now)
    today = n.date()
    out = []
    for mode in modes_qs().filter(enabled=True, auto_run_time__isnull=False):
        start = datetime.combine(today, mode.auto_run_time, tzinfo=IST)
        deadline = start + timedelta(minutes=LATE_START_GRACE_MINUTES)
        end = datetime.combine(today, mode.window_end, tzinfo=IST)
        if end > start:
            deadline = max(deadline, end)
        if not (start <= n < deadline):
            continue  # not yet, or the window passed while the scheduler was down: no late runs
        if mode.runs.filter(trading_date=today, trigger="scheduler").exists():
            continue
        out.append(mode)
    return out


def auto_run(now=None):
    """Job (every 60 s): start each mode's run once at its auto-run time on trading days. Never raises."""
    try:
        now = now or timezone.now()
        stale = finalize_stale(now)
        is_open, reason = trading_day(today_ist(now))
        if not is_open:
            return f"closed stale run(s): {stale}" if stale else None
        started = []
        for mode in due_modes(now):
            try:
                run = start_run(mode, trigger="scheduler", now=now)
                started.append(f"{mode.code} {run.status}")
            except IntegrityError:
                continue  # another worker started it
            except RunError as e:
                log.info("bodeod: %s", e)
            except Exception:
                log.exception("bodeod: scheduled run of %s failed", mode.code)
        if started:
            return "started " + ", ".join(started)
        return None
    except Exception:
        log.exception("bodeod.auto_run failed")
        return "error"


def schedule_for(mode, now=None):
    """Next automatic start (IST datetime) for a mode, or None."""
    if not mode.enabled or not mode.auto_run_time:
        return None
    n = now_ist(now)
    day = n.date()
    for _ in range(40):
        is_open, _reason = trading_day(day)
        at = datetime.combine(day, mode.auto_run_time, tzinfo=IST)
        if is_open and (day > n.date() or (at >= n and not mode.runs.filter(trading_date=day, trigger="scheduler").exists())):
            return at
        day += timedelta(days=1)
    return None


# ------------------------------------------------------------------ holidays CSV
DATE_FORMATS = ("%Y-%m-%d", "%d-%m-%Y", "%d/%m/%Y", "%d-%b-%Y", "%d %b %Y", "%d-%B-%Y", "%d %B %Y", "%d.%m.%Y")
EXCHANGE_CODES = {code for code, _ in Holiday.EXCHANGES}


def parse_date(value):
    value = (value or "").strip()
    for fmt in DATE_FORMATS:
        try:
            return datetime.strptime(value, fmt).date()
        except ValueError:
            continue
    return None


@dataclass
class CsvImport:
    rows: list = field(default_factory=list)      # [(exchange, date, description)]
    errors: list = field(default_factory=list)    # ["line 3: ..."]


def parse_holidays_csv(data, default_exchange="NSE"):
    """Parse an uploaded holiday CSV (bytes or str). Columns: date, description (or holiday/name), optional exchange."""
    out = CsvImport()
    if isinstance(data, bytes):
        if len(data) > MAX_CSV_BYTES:
            out.errors.append(f"File is larger than {MAX_CSV_BYTES // 1024} KB.")
            return out
        try:
            data = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            out.errors.append("File is not UTF-8 text.")
            return out
    reader = csv.reader(io.StringIO(data))
    header = None
    for row in reader:
        if any(c.strip() for c in row):
            header = [c.strip().lower() for c in row]
            break
    if not header:
        out.errors.append("The file is empty.")
        return out

    def col(*names):
        for n in names:
            if n in header:
                return header.index(n)
        return None

    i_date = col("date", "holiday date")
    i_desc = col("description", "holiday", "name", "holidays", "occasion")
    i_exch = col("exchange", "segment_exchange", "market")
    if i_date is None or i_desc is None:
        out.errors.append("Header must contain 'date' and 'description' columns (optional 'exchange').")
        return out
    seen = set()
    for line_no, row in enumerate(reader, start=2):
        if not any(c.strip() for c in row):
            continue
        if len(out.rows) >= MAX_CSV_ROWS:
            out.errors.append(f"Stopped after {MAX_CSV_ROWS} rows.")
            break
        get = lambda i: row[i].strip() if i is not None and i < len(row) else ""  # noqa: E731
        d = parse_date(get(i_date))
        desc = get(i_desc)
        exch = (get(i_exch) or default_exchange).upper()
        if d is None:
            out.errors.append(f"line {line_no}: invalid date “{get(i_date)}” (use YYYY-MM-DD or DD-Mon-YYYY)")
            continue
        if not desc:
            out.errors.append(f"line {line_no}: description is empty")
            continue
        if exch not in EXCHANGE_CODES:
            out.errors.append(f"line {line_no}: unknown exchange “{exch}” (use ALL, NSE, BSE or MCX)")
            continue
        if (exch, d) in seen:
            continue
        seen.add((exch, d))
        out.rows.append((exch, d, desc[:200]))
    return out


def import_holidays(rows, source="csv"):
    """Upsert parsed rows. Returns (created, updated)."""
    created = updated = 0
    with transaction.atomic():
        for exch, d, desc in rows:
            obj, was_created = Holiday.objects.update_or_create(
                tenant_key=tenant(), exchange=exch, date=d, defaults={"description": desc, "source": source})
            created += was_created
            updated += not was_created
    return created, updated


def year_bounds(year):
    return date(year, 1, 1), date(year, 12, 31)


def checklist_items(mode=None):
    qs = ChecklistItem.objects.filter(mode__tenant_key=tenant()).select_related("mode")
    if mode is not None:
        qs = qs.filter(mode=mode)
    return qs.order_by("mode__window_start", "mode__code", "order", "pk")
