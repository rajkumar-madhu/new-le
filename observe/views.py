import csv
import hmac
import io
from datetime import timedelta

from django.conf import settings
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.db import IntegrityError, transaction
from django.db.models import Count, Q
from django.http import JsonResponse, StreamingHttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from core.access import can, require
from core.audit import audit

from . import services
from .forms import ExporterForm, ImportForm
from .models import CATEGORY_STYLE, EXPORTER_TYPES, Category, Exporter, ExporterStatus, LogLevel

PER_CHOICES = (10, 20, 50, 100)
# a % change against a tiny previous period is noise (2 -> 400 lines = +19,900 %): only show it above these bases
MIN_BASE_LOGS = 50
MIN_BASE_EVENTS = 5
EXPORT_LIMIT = 100_000
LEGEND = [("active", "Active", "#16a34a"), ("inactive", "Inactive", "#94a3b8"), ("error", "Error", "#ef4444"),
          ("not_configured", "Not Configured", "#f59e0b")]
SEVERITIES = [("critical", "Critical"), ("warning", "Warning"), ("info", "Info"), ("ok", "Resolved")]


# ------------------------------------------------------------------ helpers
def _per_page(request, default=10):
    try:
        return max(5, min(100, int(request.GET.get("per", default))))
    except (TypeError, ValueError):
        return default


def _query(request, *drop):
    q = request.GET.copy()
    for k in ("page",) + drop:
        q.pop(k, None)
    return q


def _wants_json(request):
    return request.headers.get("Accept", "").startswith("application/json")


def _next(request, fallback):
    nxt = request.POST.get("next") or request.GET.get("next") or ""
    if nxt and url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()}, require_https=request.is_secure()):
        return nxt
    return fallback


def _deny(request, text="You do not have permission to do that."):
    if _wants_json(request):
        return JsonResponse({"error": text}, status=403)
    messages.error(request, text)
    return redirect(_next(request, reverse("observe:exporters")))


def _perms(request):
    return {"can_operate": can(request.user, "operate"), "can_admin": can(request.user, "admin")}


def _exporter(request, pk):
    return get_object_or_404(services.exporters_for(request.user), pk=pk)


def _pct(n, total):
    return round(100.0 * n / total, 1) if total else 0


def _csv_safe(value):
    """Neutralise spreadsheet formulas in exported cells."""
    s = "" if value is None else str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


class _Echo:
    def write(self, value):
        return value


def _stream_csv(filename, header, rows):
    writer = csv.writer(_Echo())

    def gen():
        yield writer.writerow(header)
        for r in rows:
            yield writer.writerow([_csv_safe(v) for v in r])
    resp = StreamingHttpResponse(gen(), content_type="text/csv; charset=utf-8")
    resp["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp


# ------------------------------------------------------------------ exporters page
def _filter_exporters(request, qs, with_category=True):
    q = request.GET.get("q", "").strip()
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(exporter_type__icontains=q) | Q(target__icontains=q)
                       | Q(metrics_url__icontains=q) | Q(description__icontains=q))
    if request.GET.get("status") in ExporterStatus.values:
        qs = qs.filter(status=request.GET["status"])
    if request.GET.get("site"):
        qs = qs.filter(site=request.GET["site"])
    if with_category and request.GET.get("category") in Category.values:
        qs = qs.filter(category=request.GET["category"])
    return qs


@require("view")
@require_GET
def exporters(request):
    now = timezone.now()
    scope = services.exporters_for(request.user)
    total = scope.count()
    health = {k: 0 for k in ExporterStatus.values}
    for row in scope.order_by().values("status").annotate(n=Count("id")):
        health[row["status"]] = row["n"]
    before = scope.filter(created_at__lte=now - timedelta(days=7)).count()

    # category strip: counts respect search/status/site but not the category itself
    strip_qs = _filter_exporters(request, scope, with_category=False)
    cat_counts = dict(strip_qs.order_by().values_list("category").annotate(n=Count("id")))
    category = request.GET.get("category") if request.GET.get("category") in Category.values else ""
    cats = [{"name": c, "count": cat_counts.get(c, 0), "icon": CATEGORY_STYLE[c][0], "color": CATEGORY_STYLE[c][1]}
            for c in Category.values]

    page = Paginator(_filter_exporters(request, scope).order_by("name"), _per_page(request)).get_page(request.GET.get("page"))
    logs = services.logs_for(request.user)
    day = logs.filter(ts__gte=now - timedelta(hours=24))
    names = [e.name for e in page]
    per_source = dict(day.filter(source__in=names).order_by().values_list("source").annotate(n=Count("id")))
    for e in page:
        e.logs24 = per_source.get(e.name, 0)
        e.can_edit = services.can_manage(request.user, "operate", e.site)
        e.can_delete = services.can_manage(request.user, "admin", e.site)

    logs24 = day.count()
    logs_prev = logs.filter(ts__gte=now - timedelta(hours=48), ts__lt=now - timedelta(hours=24)).count()
    events = services.events_for(request.user)
    events24 = events.filter(occurred_at__gte=now - timedelta(hours=24)).count()
    events_prev = events.filter(occurred_at__gte=now - timedelta(hours=48), occurred_at__lt=now - timedelta(hours=24)).count()

    top = list(day.order_by().values("source").annotate(n=Count("id")).order_by("-n", "source")[:8])
    legend = [{"key": k, "label": label, "color": color, "n": health[k], "pct": _pct(health[k], total)}
              for k, label, color in LEGEND]
    tail_sources = sorted(set(scope.values_list("name", flat=True)[:200]) | {r["source"] for r in top}, key=str.lower)
    ctx = {
        "page": page, "query": _query(request), "strip_query": _query(request, "category"), "category": category,
        "total": total, "health": health, "pct": {k: _pct(v, total) for k, v in health.items()},
        "total_delta": services.change_pct(total, before) if before else None,
        "logs24": logs24, "logs_delta": services.change_pct(logs24, logs_prev) if logs_prev >= MIN_BASE_LOGS else None,
        "events24": events24, "events_delta": services.change_pct(events24, events_prev) if events_prev >= MIN_BASE_EVENTS else None,
        "cats": cats, "filtered_total": strip_qs.count(), "legend": legend,
        "donut": {"segments": [{"label": s["label"], "value": s["n"], "color": s["color"]} for s in legend],
                  "center": {"value": str(total), "label": "Exporters"}, "thickness": 22},
        "trend": services.logs_trend(logs, now), "top": top, "top_max": top[0]["n"] if top else 0,
        "recent_events": events.order_by("-occurred_at")[:8],
        "tail": [services.log_row(e) for e in logs.filter(ts__gte=now - timedelta(hours=1))[:12]],
        "tail_sources": tail_sources, "categories": Category.choices, "statuses": ExporterStatus.choices,
        "sites": services.site_names(scope), "ingest_configured": bool(settings.LOG_INGEST_TOKEN),
        **_perms(request),
    }
    return render(request, "observe/exporters.html", ctx)


@require("view")
@require_GET
def exporter_detail(request, pk):
    exp = _exporter(request, pk)
    now = timezone.now()
    logs = services.logs_for(request.user).filter(source=exp.name)
    ctx = {
        "exp": exp, "logs": logs[:25], "logs24": logs.filter(ts__gte=now - timedelta(hours=24)).count(),
        "events": services.events_for(request.user).filter(fingerprint=f"exporter:{exp.pk}")[:20],
        "trend": services.logs_trend(logs, now),
        "can_edit": services.can_manage(request.user, "operate", exp.site),
        "can_delete": services.can_manage(request.user, "admin", exp.site),
    }
    return render(request, "observe/exporter_detail.html", ctx)


@require("operate")
@require_http_methods(["GET", "POST"])
def exporter_form(request, pk=None):
    exp = _exporter(request, pk) if pk else None
    if exp and not services.can_manage(request.user, "operate", exp.site):
        raise PermissionDenied
    initial = {}
    if not exp:
        if request.GET.get("category") in Category.values:
            initial["category"] = request.GET["category"]
        if request.GET.get("site"):
            initial["site"] = request.GET["site"]
    form = ExporterForm(request.POST or None, instance=exp, initial=initial)
    if request.method == "POST" and form.is_valid():
        site = form.cleaned_data.get("site", "")
        if not services.can_manage(request.user, "operate", site):
            form.add_error("site", "You cannot manage exporters on this site.")
        else:
            changed = list(form.changed_data)
            obj = form.save(commit=False)
            obj.tenant_key = settings.LINKEDEYE_TENANT
            was_checked = bool(exp) and exp.status in (ExporterStatus.ACTIVE, ExporterStatus.ERROR)
            needs_scrape = obj.apply_config_status(url_changed=bool(exp) and "metrics_url" in changed)
            # scrape right away for a new exporter, or when its endpoint or enabled flag changed
            needs_scrape = needs_scrape and (not exp or bool({"metrics_url", "enabled"} & set(changed)))
            try:
                with transaction.atomic():
                    obj.save()
            except IntegrityError:
                form.add_error("name", "An exporter with this name already exists.")
            else:
                if exp and was_checked and obj.config_status() is not None:
                    services.close_failure(obj, "Disabled" if not obj.enabled else "Metrics URL removed")
                if exp:
                    audit(request, "update", obj, changed=changed)
                else:
                    audit(request, "create", obj, exporter_type=obj.exporter_type, category=obj.category,
                          metrics_url=obj.metrics_url, site=obj.site)
                note = ""
                if needs_scrape:
                    res = services.check_exporters([obj])[0][1]
                    obj.refresh_from_db()
                    note = (f" First scrape: {res.samples} samples in {res.response_ms:g} ms." if res.ok
                            else f" First scrape failed: {res.error}")
                elif not obj.enabled:
                    note = " It is disabled, so it is not scraped."
                elif not obj.metrics_url:
                    note = " It has no metrics URL, so it shows as Not Configured until one is set."
                msg = (messages.warning if needs_scrape and obj.status == ExporterStatus.ERROR else messages.success)
                msg(request, f"{'Saved' if exp else 'Added'} “{obj.name}”.{note}")
                return redirect(obj.get_absolute_url())
    return render(request, "observe/exporter_form.html", {"form": form, "exp": exp})


@require("admin")
@require_POST
def exporter_delete(request, pk):
    exp = _exporter(request, pk)
    if not services.can_manage(request.user, "admin", exp.site):
        return _deny(request)
    name = exp.name
    services.close_failure(exp, "Exporter deleted")
    audit(request, "delete", exp, name=name, exporter_type=exp.exporter_type, category=exp.category,
          metrics_url=exp.metrics_url, site=exp.site)
    exp.delete()
    messages.success(request, f"Deleted exporter “{name}”. Its log lines are kept until retention removes them.")
    return redirect(_next(request, reverse("observe:exporters")))


@require("operate")
@require_POST
def exporter_check(request, pk):
    exp = _exporter(request, pk)
    if not services.can_manage(request.user, "operate", exp.site):
        return _deny(request)
    if not exp.scrapeable:
        reason = "it is disabled" if not exp.enabled else "it has no metrics URL"
        summary = f"{exp.name} was not checked: {reason}."
        audit(request, "run", exp, check="scrape", result_status=exp.status, skipped=reason, result="skipped")
        messages.warning(request, summary)
        if _wants_json(request):
            return JsonResponse({"status": exp.status, "summary": summary}, status=409)
        return redirect(_next(request, exp.get_absolute_url()))
    res = services.check_exporters([exp])[0][1]
    exp.refresh_from_db()
    audit(request, "run", exp, check="scrape", result_status=exp.status, ok=res.ok, samples=res.samples,
          response_ms=res.response_ms, error=res.error)
    summary = (f"{exp.name}: active, {res.samples} samples in {res.response_ms:g} ms." if res.ok
               else f"{exp.name}: error – {res.error}")
    # also for the fetch() path: app.js reloads the page, which then shows the message
    (messages.success if res.ok else messages.warning)(request, summary)
    if _wants_json(request):
        return JsonResponse({"status": exp.status, "summary": summary, "samples": res.samples,
                             "response_ms": res.response_ms, "error": res.error})
    return redirect(_next(request, exp.get_absolute_url()))


@require("operate")
@require_POST
def exporter_check_all(request):
    qs = _filter_exporters(request, services.exporters_for(request.user)).filter(enabled=True).exclude(metrics_url="")
    items = [e for e in qs.order_by("name") if services.can_manage(request.user, "operate", e.site)]
    limited = len(items) > services.CHECK_ALL_LIMIT
    results = services.check_exporters(items[:services.CHECK_ALL_LIMIT])
    ok = sum(1 for _e, r in results if r.ok)
    audit(request, "run", None, object_type="observe.exporter", check="scrape", checked=len(results), active=ok)
    summary = f"Scraped {len(results)} exporter(s): {ok} active, {len(results) - ok} error."
    if not results:
        summary = "No enabled exporters with a metrics URL to check."
    if limited:
        summary += f" Only the first {services.CHECK_ALL_LIMIT} were checked now; the rest are scraped every minute."
    messages.success(request, summary)
    if _wants_json(request):
        return JsonResponse({"checked": len(results), "active": ok, "summary": summary})
    return redirect(_next(request, reverse("observe:exporters")))


@require("view")
@require_GET
def exporters_export(request):
    qs = _filter_exporters(request, services.exporters_for(request.user)).order_by("name")
    rows = ([e.name, e.exporter_type, e.category, e.target, e.metrics_url, e.site, "yes" if e.enabled else "no",
             e.get_status_display(), e.last_seen.isoformat() if e.last_seen else "", e.samples if e.samples is not None else "",
             "" if e.last_scrape_ms is None else round(e.last_scrape_ms), e.last_error, e.description]
            for e in qs.iterator())
    return _stream_csv("exporters.csv", ["name", "type", "category", "target", "metrics_url", "site", "enabled", "status",
                                         "last_seen", "samples", "last_scrape_ms", "last_error", "description"], rows)


IMPORT_MAX_BYTES = 1024 * 1024
IMPORT_MAX_ROWS = 1000
TRUE_WORDS = {"1", "true", "yes", "y", "on", "enabled"}


@require("operate")
@require_http_methods(["GET", "POST"])
def exporters_import(request):
    form = ImportForm(request.POST or None, request.FILES or None)
    report = None
    if request.method == "POST" and form.is_valid():
        f = form.cleaned_data["file"]
        if f.size > IMPORT_MAX_BYTES:
            form.add_error("file", "The file is larger than 1 MB.")
        else:
            try:
                text = f.read().decode("utf-8-sig")
            except UnicodeDecodeError:
                form.add_error("file", "The file must be UTF-8 encoded CSV.")
            else:
                report = _import_rows(request, text, form.cleaned_data["update_existing"])
                if report is not None and not report.get("fatal"):
                    audit(request, "import", None, object_type="observe.exporter", created=report["created"],
                          updated=report["updated"], skipped=len(report["errors"]))
                    text_msg = f"Import finished: {report['created']} created, {report['updated']} updated"
                    if report["errors"]:
                        text_msg += f", {len(report['errors'])} row(s) skipped (see below)"
                        messages.warning(request, text_msg + ".")
                    else:
                        messages.success(request, text_msg + ". New exporters are scraped within a minute.")
                        return redirect("observe:exporters")
    return render(request, "observe/exporter_import.html", {"form": form, "report": report,
                                                            "categories": Category.values})


def _import_rows(request, text, update_existing):
    reader = csv.DictReader(io.StringIO(text))
    try:
        fields = {(h or "").strip().lower() for h in (reader.fieldnames or [])}
    except csv.Error as e:
        return {"fatal": f"The header row could not be read: {e}.", "errors": [], "created": 0, "updated": 0}
    if not {"name", "type", "category"} <= fields:
        return {"fatal": "The header row must contain at least: name, type, category.", "errors": [], "created": 0, "updated": 0}
    created = updated = 0
    errors = []
    cats = {c.lower(): c for c in Category.values}
    rows = enumerate(reader, 2)
    while True:
        try:
            no, raw = next(rows)
        except StopIteration:
            break
        except csv.Error as e:      # e.g. a field over the csv module's 128 KB limit
            errors.append({"row": reader.line_num, "error": f"Stopped: the CSV could not be read here ({e})."})
            break
        if no - 1 > IMPORT_MAX_ROWS:
            errors.append({"row": no, "error": f"Stopped: more than {IMPORT_MAX_ROWS} rows."})
            break
        row = {(k or "").strip().lower(): (v or "").strip() for k, v in raw.items() if k}
        if not any(row.values()):
            continue
        cat = cats.get(row.get("category", "").lower())
        if not cat:
            errors.append({"row": no, "error": f"Unknown category “{row.get('category', '')}”."})
            continue
        # a blank "enabled" cell keeps the default (enabled), like every other optional column
        data = {"name": row.get("name", ""), "exporter_type": row.get("type", ""), "category": cat,
                "target": row.get("target", ""), "metrics_url": row.get("metrics_url", ""), "site": row.get("site", ""),
                "enabled": (row.get("enabled") or "yes").lower() in TRUE_WORDS, "description": row.get("description", "")}
        existing = Exporter.objects.filter(tenant_key=settings.LINKEDEYE_TENANT, name__iexact=data["name"]).first()
        if existing and not update_existing:
            errors.append({"row": no, "error": f"“{data['name']}” already exists (tick “Update exporters that already exist”)."})
            continue
        if existing and not services.can_manage(request.user, "operate", existing.site):
            errors.append({"row": no, "error": f"You cannot manage “{existing.name}”."})
            continue
        form = ExporterForm(data, instance=existing)
        if data["site"] and data["site"] not in dict(form.fields["site"].choices):
            form.fields["site"].choices = list(form.fields["site"].choices) + [(data["site"], data["site"])]
        if not form.is_valid():
            msg = "; ".join(f"{k}: {' '.join(v)}" for k, v in form.errors.items())
            errors.append({"row": no, "error": msg})
            continue
        if not services.can_manage(request.user, "operate", form.cleaned_data.get("site", "")):
            errors.append({"row": no, "error": f"You cannot manage exporters on site “{data['site']}”."})
            continue
        changed = list(form.changed_data)
        existing_checked = bool(existing) and existing.status in (ExporterStatus.ACTIVE, ExporterStatus.ERROR)
        obj = form.save(commit=False)
        obj.tenant_key = settings.LINKEDEYE_TENANT
        obj.apply_config_status(url_changed=bool(existing) and "metrics_url" in changed)
        try:
            with transaction.atomic():
                obj.save()
        except IntegrityError:
            errors.append({"row": no, "error": f"“{data['name']}” already exists."})
            continue
        if existing and existing_checked and obj.config_status() is not None:
            services.close_failure(obj, "Disabled" if not obj.enabled else "Metrics URL removed")
        if existing:
            updated += 1
            audit(request, "update", obj, changed=changed, via="import")
        else:
            created += 1
            audit(request, "create", obj, via="import", category=obj.category, site=obj.site)
    return {"created": created, "updated": updated, "errors": errors}


@require("view")
@require_GET
def exporters_docs(request):
    return render(request, "observe/docs.html", {
        "ingest_configured": bool(settings.LOG_INGEST_TOKEN),
        "ingest_url": request.build_absolute_uri(reverse("observe:log_ingest")),
        "retention_days": getattr(settings, "LOG_RETENTION_DAYS", 14),
        "max_entries": services.MAX_ENTRIES, "max_kb": services.MAX_BYTES // 1024,
        "categories": Category.values, "types": EXPORTER_TYPES,
    })


# ------------------------------------------------------------------ logs
def _parse_local(value):
    if not value:
        return None
    try:
        dt = parse_datetime(value.strip())
    except ValueError:          # well formed but impossible, e.g. 2026-02-30T10:00
        return None
    if dt is None:
        return None
    return timezone.make_aware(dt) if timezone.is_naive(dt) else dt


def _filter_logs(g, qs, default_range="24h"):
    """Apply q/level/source/site/host/time filters from the query dict `g`. Returns (qs, info)."""
    q = g.get("q", "").strip()
    if q:
        qs = qs.filter(Q(message__icontains=q) | Q(host__icontains=q) | Q(source__icontains=q))
    level = g.get("level", "")
    if level in LogLevel.values:
        qs = qs.filter(level=level)
    elif level == "WARN+":
        qs = qs.filter(level__in=["WARN", "ERROR", "CRITICAL"])
    elif level == "ERROR+":
        qs = qs.filter(level__in=["ERROR", "CRITICAL"])
    if g.get("source"):
        qs = qs.filter(source=g["source"])
    if g.get("site"):
        qs = qs.filter(site=g["site"])
    if g.get("host"):
        qs = qs.filter(host=g["host"])
    rng = g.get("range", default_range)
    since = until = None
    if rng == "custom":
        since, until = _parse_local(g.get("since")), _parse_local(g.get("until"))
    else:
        rng, since = services.since_for(rng, default_range)
    if since:
        qs = qs.filter(ts__gte=since)
    if until:
        qs = qs.filter(ts__lte=until)
    return qs, {"range": rng, "since": since, "until": until}


def _filter_events(request, qs, prefix=""):
    g = request.GET
    sev, src = g.get(prefix + "severity", ""), g.get(prefix + "source", "")
    if sev in dict(SEVERITIES):
        qs = qs.filter(severity=sev)
    if src:
        qs = qs.filter(source=src)
    if not prefix:
        q = g.get("q", "").strip()
        if q:
            qs = qs.filter(Q(title__icontains=q) | Q(message__icontains=q) | Q(fingerprint__icontains=q))
        if g.get("site"):
            qs = qs.filter(site=g["site"])
        if g.get("kind"):
            qs = qs.filter(kind=g["kind"])
        if g.get("fingerprint"):
            qs = qs.filter(fingerprint=g["fingerprint"])
        rng, since = services.since_for(g.get("range", "7d"), "7d")
        if since:
            qs = qs.filter(occurred_at__gte=since)
    return qs


def _level_links(request, counts):
    base = _query(request, "level")
    cur = request.GET.get("level", "")
    links = [{"value": "", "label": "All levels", "n": sum(counts.values()), "href": base.urlencode(), "on": not cur}]
    for v, label in LogLevel.choices:
        q = base.copy()
        q["level"] = v
        links.append({"value": v, "label": label, "n": counts.get(v, 0), "href": q.urlencode(), "on": cur == v})
    return links


def _live_params(request, info):
    p = _query(request, "per", "eseverity", "esource")
    p["range"] = info["range"]
    return p.urlencode()


@require("view")
@require_GET
def logs(request):
    now = timezone.now()
    base = services.logs_for(request.user)
    qs, info = _filter_logs(request.GET, base)
    page = Paginator(qs.order_by("-ts", "-id"), _per_page(request, 50)).get_page(request.GET.get("page"))
    level_counts = {lv: 0 for lv in LogLevel.values}
    # level KPIs follow every filter except the level itself
    no_level = request.GET.copy()
    no_level.pop("level", None)
    lv_qs, _ = _filter_logs(no_level, base)
    for lv, n in lv_qs.order_by().values_list("level").annotate(n=Count("id")):
        level_counts[lv] = n
    sources = sorted(set(base.filter(ts__gte=now - timedelta(days=7)).order_by().values_list("source", flat=True).distinct()[:300])
                     | set(services.exporters_for(request.user).values_list("name", flat=True)), key=str.lower)
    if request.GET.get("source") and request.GET["source"] not in sources:
        sources.append(request.GET["source"])
    events = _filter_events(request, services.events_for(request.user), prefix="e")
    ev_sources = sorted(services.events_for(request.user).order_by().values_list("source", flat=True).distinct())
    ctx = {
        "page": page, "query": _query(request), "info": info, "ranges": services.RANGES, "levels": LogLevel.choices,
        "level_counts": level_counts, "level_total": sum(level_counts.values()), "sources": sources,
        "sites": services.site_names(base.filter(ts__gte=now - timedelta(days=7)), services.exporters_for(request.user)),
        "events": events.order_by("-occurred_at")[:15], "ev_sources": ev_sources, "severities": SEVERITIES,
        "ev_query": _query(request, "eseverity", "esource"),
        "ingest_configured": bool(settings.LOG_INGEST_TOKEN),
        "retention_days": getattr(settings, "LOG_RETENTION_DAYS", 14),
        "level_links": _level_links(request, level_counts),
        "host_clear": _query(request, "host").urlencode(),
        "live_ok": page.number == 1 and not info.get("until"),
        "live_params": _live_params(request, info),
        "max_id": max((e.pk for e in page), default=0),
    }
    return render(request, "observe/logs.html", ctx)


@require("view")
@require_GET
def logs_feed(request):
    """Small JSON endpoint for the live log panels: newest first, optionally only rows after `after` (an id)."""
    qs, _info = _filter_logs(request.GET, services.logs_for(request.user), default_range="1h")
    try:
        limit = max(1, min(100, int(request.GET.get("limit", 20))))
    except ValueError:
        limit = 20
    try:
        after = int(request.GET.get("after", 0))
    except ValueError:
        after = 0
    if after:
        qs = qs.filter(id__gt=after)
    rows = [services.log_row(e) for e in qs.order_by("-ts", "-id")[:limit]]
    newest = services.logs_for(request.user).order_by("-id").values_list("id", flat=True).first() or 0
    return JsonResponse({"rows": rows, "last_id": max([newest, after] + [r["id"] for r in rows]),
                         "now": timezone.now().isoformat()})


@require("view")
@require_GET
def logs_export(request):
    qs, _info = _filter_logs(request.GET, services.logs_for(request.user))
    rows = ([e.ts.isoformat(), e.level, e.source, e.host, e.site, e.message, e.attributes or ""]
            for e in qs.order_by("-ts", "-id")[:EXPORT_LIMIT].iterator())
    return _stream_csv("logs.csv", ["ts", "level", "source", "host", "site", "message", "attributes"], rows)


# ------------------------------------------------------------------ events
@require("view")
@require_GET
def events(request):
    now = timezone.now()
    base = services.events_for(request.user)
    qs = _filter_events(request, base)
    page = Paginator(qs.order_by("-occurred_at", "-id"), _per_page(request, 20)).get_page(request.GET.get("page"))
    day = base.filter(occurred_at__gte=now - timedelta(hours=24))
    sev_counts = dict(day.order_by().values_list("severity").annotate(n=Count("id")))
    groups = []
    for ev in page:
        d = timezone.localtime(ev.occurred_at).date()
        if not groups or groups[-1]["date"] != d:
            groups.append({"date": d, "items": []})
        groups[-1]["items"].append(ev)
    ctx = {
        "page": page, "groups": groups, "query": _query(request), "severities": SEVERITIES,
        "sev_counts": {k: sev_counts.get(k, 0) for k, _ in SEVERITIES}, "day_total": sum(sev_counts.values()),
        "sources": sorted(base.order_by().values_list("source", flat=True).distinct()),
        "kinds": sorted(base.order_by().values_list("kind", flat=True).distinct()),
        "sites": sorted(s for s in base.order_by().values_list("site", flat=True).distinct() if s),
        "ranges": [r for r in services.RANGES if r[0] != "15m"],
        "range": services.since_for(request.GET.get("range", "7d"), "7d")[0],   # an unknown value falls back to 7d
        "today": timezone.localdate(), "yesterday": timezone.localdate() - timedelta(days=1),
    }
    return render(request, "observe/events.html", ctx)


@require("view")
@require_GET
def events_export(request):
    qs = _filter_events(request, services.events_for(request.user)).order_by("-occurred_at", "-id")
    rows = ([e.occurred_at.isoformat(), e.severity, e.source, e.kind, e.site, e.title, e.message, e.fingerprint]
            for e in qs[:EXPORT_LIMIT].iterator())
    return _stream_csv("events.csv", ["occurred_at", "severity", "source", "kind", "site", "title", "message", "fingerprint"], rows)


# ------------------------------------------------------------------ ingest API
def _api_error(text, status):
    return JsonResponse({"error": text}, status=status)


@csrf_exempt
def log_ingest(request):
    """POST /api/v1/logs/ with `Authorization: Bearer <LINKEDEYE_LOG_INGEST_TOKEN>`.
    Body: a JSON array (or NDJSON) of {ts?, source, level, message, host?, site?, attributes?}."""
    if request.method != "POST":
        resp = _api_error("Use POST", 405)
        resp["Allow"] = "POST"
        return resp
    token = getattr(settings, "LOG_INGEST_TOKEN", "") or ""
    if not token:
        return _api_error("Log ingest is disabled: set LINKEDEYE_LOG_INGEST_TOKEN on the server.", 503)
    auth = request.headers.get("Authorization", "")
    scheme, _, given = auth.partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(given.strip().encode(), token.encode()):
        resp = _api_error("Invalid or missing bearer token", 401)
        resp["WWW-Authenticate"] = 'Bearer realm="linkedeye-logs"'
        return resp
    try:
        length = int(request.META.get("CONTENT_LENGTH") or 0)
    except ValueError:
        length = 0
    if length > services.MAX_BYTES:
        return _api_error(f"Request body exceeds {services.MAX_BYTES // 1024} KB", 413)
    try:
        body = request.read(services.MAX_BYTES + 1)
        entries = services.parse_payload(body, request.content_type or "")
    except services.IngestError as e:
        return _api_error(str(e), e.status)
    summary = services.ingest(entries)
    status = 200 if summary["accepted"] or not summary["rejected"] else 400
    return JsonResponse(summary, status=status)
