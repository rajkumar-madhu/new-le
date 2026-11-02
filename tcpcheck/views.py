import csv
from datetime import timedelta
from decimal import Decimal

from django.apps import apps
from django.conf import settings
from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Q
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_http_methods, require_POST

from core.access import can, require, visible_sites
from core.audit import audit

from . import services, stats, uptime
from .forms import COMMON_PORTS, SlaForm, TcpCheckForm
from .models import DEFAULT_SLA, SlaTarget, Status, TcpCheck, TcpResult

RUN_ALL_LIMIT = 200
RUN_ALL_WORKERS = 32        # "Run Check Now" waits for the whole batch: probe it wider than the scheduler does
SORT_CHOICES = [("uptime", "lowest uptime"), ("sla", "SLA breaches"), ("name", "name"), ("type", "type"), ("site", "site")]
FORM_FIELDS = ["name", "host", "port", "interval_seconds", "site", "tags", "expect_banner", "degraded_ms",
               "timeout_seconds", "description", "enabled"]


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


def _deny(request, text="You do not have permission to do that.", fallback=None):
    if _wants_json(request):
        return JsonResponse({"error": text}, status=403)
    messages.error(request, text)
    return redirect(_next(request, fallback or reverse("tcpcheck:index")))


def _cell(value):
    """CSV cell safe to open in a spreadsheet: text starting with = + - @ (or a control char) is not a formula."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def _row(values):
    return [_cell(v) for v in values]


def _perms(request):
    u = request.user
    return {"can_operate": can(u, "operate"), "can_admin": can(u, "admin")}


def _change(now, then):
    if now is None or not then:
        return None
    return round(100.0 * (now - then) / then)


def _filtered(request, qs):
    g = request.GET
    q = g.get("q", "").strip()
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(host__icontains=q) | Q(tags__icontains=q) | Q(description__icontains=q))
    if g.get("site"):
        qs = qs.filter(site=g["site"])
    if g.get("status") in Status.values:
        qs = qs.filter(last_status=g["status"])
    if g.get("port", "").isdigit():
        qs = qs.filter(port=int(g["port"]))
    if g.get("enabled") in ("0", "1"):
        qs = qs.filter(enabled=g["enabled"] == "1")
    return qs


def _check(request, pk):
    return get_object_or_404(services.checks_for(request.user), pk=pk)


def _sites(request):
    return uptime.all_sites(request.user)


# ------------------------------------------------------------------ Telnet Monitoring
def _index_context(request, form, editing):
    scope = services.checks_for(request.user)
    enabled = scope.filter(enabled=True)
    checks = list(enabled)                # status counts / created dates; result queries use the subquery
    counts = stats.status_counts(checks)
    total = len(checks)
    pct = {k: (100.0 * v / total if total else 0) for k, v in counts.items()}

    page = Paginator(_filtered(request, scope), _per_page(request)).get_page(request.GET.get("page"))
    up24 = stats.uptime_map([c.pk for c in page], 24)
    u = request.user
    for c in page:
        c.uptime24 = up24.get(c.pk)
        # site-scoped operators only get actions for checks on sites they manage
        c.can_manage = services.can_manage(u, "operate", c.site)
        c.can_delete = services.can_manage(u, "admin", c.site)
    avg = stats.avg_response(enabled)
    week_ago = timezone.now() - timedelta(days=7)
    before = sum(1 for c in checks if c.created_at <= week_ago)
    all_events = request.GET.get("events") == "all"
    events = (TcpResult.objects.filter(tcp_check__in=scope).select_related("tcp_check")
              .order_by("-checked_at")[:50 if all_events else 6])
    return {
        **_perms(request),
        "page": page, "form": form, "editing": editing, "total": total, "counts": counts, "pct": pct,
        "disabled": scope.filter(enabled=False).count(),
        "avg_response": avg, "total_delta": _change(total, before) if before else None,
        "avg_delta": _change(avg, stats.avg_response(enabled, hours=24, offset_hours=24)),
        "uptime7": stats.overall_uptime(enabled, 24 * 7),
        "donut": stats.donut(counts, total), "trend": stats.response_trend(enabled),
        "history": stats.daily_history(enabled), "events": events, "all_events": all_events,
        "sites": _sites(request), "statuses": Status.choices, "ports": COMMON_PORTS,
        "query": _query(request), "query_noevents": _query(request, "events"),
    }


def _initial_site(user):
    """Default site for the add form: "All Sites" when the user may use it, else the first site they manage."""
    if services.can_manage(user, "operate", "All Sites"):
        return "All Sites"
    for name in sorted(visible_sites(user) or ()):
        if services.can_manage(user, "operate", name):
            return name
    return "All Sites"


@require("view")
def index(request):
    form = TcpCheckForm(initial={"site": _initial_site(request.user)})
    return render(request, "tcpcheck/index.html", _index_context(request, form, None))


def _save(request, form, editing):
    obj = form.save(commit=False)
    if not services.can_manage(request.user, "operate", obj.site):
        form.add_error("site", f"You cannot add or change checks for “{obj.site}”.")
        return None
    if editing is not None and not services.can_manage(request.user, "operate", editing.site):
        form.add_error(None, "You cannot change checks on this check's current site.")
        return None
    obj.tenant_key = settings.LINKEDEYE_TENANT
    obj.save()
    return obj


@require("operate")
@require_http_methods(["GET", "POST"])
def create(request):
    if request.method == "GET":
        return redirect(reverse("tcpcheck:index") + "#form")
    form = TcpCheckForm(request.POST)
    if form.is_valid():
        obj = _save(request, form, None)
        if obj is not None:
            audit(request, "create", obj, host=obj.host, port=obj.port, site=obj.site, interval=obj.interval_seconds,
                  expect_banner=obj.expect_banner)
            if obj.enabled:
                status = services.run_checks([obj])[0]
                messages.success(request, f"Saved “{obj.name}” and ran its first check: {Status(status).label}.")
            else:
                messages.success(request, f"Saved “{obj.name}” (disabled, not checked).")
            return redirect("tcpcheck:index")
    return render(request, "tcpcheck/index.html", _index_context(request, form, None), status=400)


@require("operate")
@require_http_methods(["GET", "POST"])
def edit(request, pk):
    editing = _check(request, pk)
    if request.method == "GET":
        if not services.can_manage(request.user, "operate", editing.site):
            return _deny(request, f"You cannot change checks for “{editing.site}”.")
        return render(request, "tcpcheck/index.html", _index_context(request, TcpCheckForm(instance=editing), editing))
    before = {f: getattr(editing, f) for f in FORM_FIELDS}
    form = TcpCheckForm(request.POST, instance=TcpCheck.objects.get(pk=editing.pk))
    if form.is_valid():
        obj = _save(request, form, editing)
        if obj is not None:
            changed = {f: [str(before[f]), str(getattr(obj, f))] for f in FORM_FIELDS if before[f] != getattr(obj, f)}
            audit(request, "update", obj, changed=changed)
            target_changed = any(f in changed for f in ("host", "port", "expect_banner", "timeout_seconds", "degraded_ms"))
            if obj.enabled and (target_changed or "enabled" in changed):
                status = services.run_checks([obj])[0]
                messages.success(request, f"Saved “{obj.name}” and re-checked it: {Status(status).label}.")
            else:
                messages.success(request, f"Saved “{obj.name}”." if changed else f"No changes to “{obj.name}”.")
            return redirect(_next(request, reverse("tcpcheck:index")))
    return render(request, "tcpcheck/index.html", _index_context(request, form, editing), status=400)


@require("admin")
@require_POST
def delete(request, pk):
    obj = _check(request, pk)
    if not services.can_manage(request.user, "admin", obj.site):
        return _deny(request)
    name = obj.name
    audit(request, "delete", obj, name=name, host=obj.host, port=obj.port, site=obj.site,
          results=obj.results.count())
    obj.delete()
    SlaTarget.objects.filter(tenant_key=settings.LINKEDEYE_TENANT, kind="tcp", object_id=pk).delete()
    messages.success(request, f"Deleted “{name}” and its check history.")
    nxt = _next(request, reverse("tcpcheck:index"))
    if nxt.rstrip("/").endswith(f"/telnet/{pk}"):
        nxt = reverse("tcpcheck:index")
    return redirect(nxt)


@require("operate")
@require_POST
def run_now(request, pk):
    obj = _check(request, pk)
    if not services.can_manage(request.user, "operate", obj.site):
        return _deny(request)
    status = services.run_checks([obj])[0]
    obj.refresh_from_db()
    audit(request, "run", obj, status=str(status), response_ms=obj.last_response_ms, error=obj.last_error)
    summary = f"{obj.name}: {Status(status).label}" + (
        f" – {obj.last_error}" if obj.last_error else
        f" in {services.fmt_ms(obj.last_response_ms)}" if obj.last_response_ms is not None else "")
    # also queued for JSON callers: the page's run buttons reload after the POST and show it there
    (messages.success if status != Status.DOWN else messages.warning)(request, summary)
    if _wants_json(request):
        return JsonResponse({"status": status, "summary": summary, "response_ms": obj.last_response_ms,
                             "error": obj.last_error})
    return redirect(_next(request, obj.get_absolute_url()))


@require("operate")
@require_POST
def run_all(request):
    qs = _filtered(request, services.checks_for(request.user)).filter(enabled=True)
    items = [c for c in qs[:RUN_ALL_LIMIT] if services.can_manage(request.user, "operate", c.site)]
    statuses = services.run_checks(items, workers=RUN_ALL_WORKERS)
    down = sum(1 for s in statuses if s == Status.DOWN)
    audit(request, "run", None, object_type="tcpcheck.tcpcheck", checks=len(items), down=down)
    summary = f"Checked {len(items)} TCP target(s): {len(items) - down} reachable, {down} down."
    if not items:
        summary = "No enabled TCP checks that you can run match these filters."
    messages.success(request, summary)
    if _wants_json(request):
        return JsonResponse({"checked": len(items), "down": down, "summary": summary})
    return redirect(_next(request, reverse("tcpcheck:index")))


@require("view")
def detail(request, pk):
    check = _check(request, pk)
    results_qs = check.results.all()
    st = request.GET.get("status")
    if st in Status.values:
        results_qs = results_qs.filter(status=st)
    page = Paginator(results_qs, _per_page(request, 20)).get_page(request.GET.get("page"))
    windows = uptime.WINDOWS
    up = {w: stats.uptime_map([check.pk], h).get(check.pk) for w, h in windows.items()}
    up.update(d1=up["24h"], d7=up["7d"], d30=up["30d"])
    sla = SlaTarget.objects.filter(tenant_key=settings.LINKEDEYE_TENANT, kind="tcp", object_id=check.pk).first()
    sla_target = sla.target if sla else DEFAULT_SLA
    sla_state = None if up["30d"] is None else ("met" if Decimal(str(round(up["30d"], 3))) >= sla_target else "breached")
    srcs = {"tcp": TcpCheck.objects.filter(pk=check.pk)}
    daily, has_daily = uptime.daily_availability(srcs, days=30)
    for s in daily["series"]:
        if s["name"] == "TCP":
            s.update({"name": "Availability", "color": stats.COLORS["online"], "width": 2, "area": True, "areaOpacity": 0.08})
    daily["series"] = [s for s in daily["series"] if s["name"] != "Overall"]
    Event = apps.get_model("core", "Event")
    events = Event.objects.filter(fingerprint=f"tcp:{check.pk}").order_by("-occurred_at")[:8]
    return render(request, "tcpcheck/detail.html", {
        **_perms(request), "check": check, "page": page, "query": _query(request), "up": up,
        "can_manage": services.can_manage(request.user, "operate", check.site),
        "can_delete": services.can_manage(request.user, "admin", check.site),
        "trend": stats.response_trend([check.pk]), "avg24": stats.avg_response([check.pk]),
        "daily": daily, "has_daily": has_daily, "sla_target": sla_target, "sla_state": sla_state,
        "sla_text": uptime.sla_text(sla_target),
        "events": events, "related": _related(check), "statuses": Status.choices,
        "result_count": check.results.count(),
    })


def _related(check):
    """Network device / CMDB CI that share this check's host, when those modules are installed."""
    out = []
    try:
        Device = apps.get_model("network", "Device")
        for d in Device.objects.filter(tenant_key=settings.LINKEDEYE_TENANT).filter(
                Q(mgmt_ip=check.host) | Q(name__iexact=check.host))[:3]:
            out.append({"kind": "Network device", "name": d.name, "status": getattr(d, "status", ""),
                        "url": d.get_absolute_url() if hasattr(d, "get_absolute_url") else ""})
    except Exception:
        pass
    try:
        from cmdb.services import find_ci
        ci = find_ci(check.host)
        if ci is not None:
            out.append({"kind": "Configuration item", "name": ci.name, "status": getattr(ci, "status", ""),
                        "url": ci.get_absolute_url() if hasattr(ci, "get_absolute_url") else ""})
    except Exception:
        pass
    return out


@require("view")
def export_csv(request):
    resp = HttpResponse(content_type="text/csv; charset=utf-8")
    resp["Content-Disposition"] = 'attachment; filename="tcp-checks.csv"'
    w = csv.writer(resp)
    w.writerow(["name", "host", "port", "site", "tags", "enabled", "status", "response_ms", "uptime_24h",
                "last_checked", "interval_s", "expect_banner", "message"])
    rows = list(_filtered(request, services.checks_for(request.user)))
    up = stats.uptime_map([c.pk for c in rows], 24)
    for c in rows:
        w.writerow(_row([c.name, c.host, c.port, c.site, c.tags, "yes" if c.enabled else "no", c.last_status,
                    "" if c.last_response_ms is None else round(c.last_response_ms, 1),
                    "" if c.pk not in up else f"{up[c.pk]:.3f}",
                    c.last_checked_at.isoformat() if c.last_checked_at else "", c.interval_seconds, c.expect_banner,
                    c.last_error]))
    return resp


@require("view")
def history_csv(request, pk):
    check = _check(request, pk)
    resp = HttpResponse(content_type="text/csv; charset=utf-8")
    resp["Content-Disposition"] = f'attachment; filename="tcp-check-{check.pk}-history.csv"'
    w = csv.writer(resp)
    w.writerow(["checked_at", "status", "response_ms", "ip", "banner", "message"])
    for r in check.results.all().iterator():
        w.writerow(_row([r.checked_at.isoformat(), r.status, "" if r.response_ms is None else r.response_ms,
                         r.ip or "", r.banner, r.message]))
    return resp


# ------------------------------------------------------------------ Uptime Checks
def _uptime_targets(request):
    g = request.GET
    kind = g.get("type") if g.get("type") in uptime.KIND_LABEL else ""
    targets = uptime.collect(request.user, kind=kind, site=g.get("site", ""), q=g.get("q", "").strip())
    status = g.get("status")
    if status in Status.values:
        targets = [t for t in targets if t.status == status]
    sla = g.get("sla")
    if sla in ("met", "breached", "nodata"):
        targets = [t for t in targets if t.sla_state == sla]
    return uptime.sort_targets(targets, g.get("sort", "status")), kind


@require("view")
def uptime_view(request):
    targets, kind = _uptime_targets(request)
    days = 7 if request.GET.get("days") == "7" else 14 if request.GET.get("days") == "14" else 30
    srcs = uptime.filtered_sources(request.user, kind=kind, site=request.GET.get("site", ""),
                                   q=request.GET.get("q", "").strip())
    daily, has_daily = uptime.daily_availability(srcs, days=days)
    page = Paginator(targets, _per_page(request, 20)).get_page(request.GET.get("page"))
    by_kind = {k: sum(1 for t in targets if t.kind == k) for k in uptime.KIND_LABEL}
    sla_counts = {s: sum(1 for t in targets if t.sla_state == s) for s in ("met", "breached", "nodata")}
    up_now = sum(1 for t in targets if t.status in ("online", "degraded"))
    down_now = sum(1 for t in targets if t.status == "down")
    total = len(targets)
    perms = _perms(request)
    for t in page:
        t.can_edit_sla = perms["can_operate"] and services.can_manage(request.user, "operate", t.site)
    with_data = sla_counts["met"] + sla_counts["breached"]
    return render(request, "tcpcheck/uptime.html", {
        **perms, "page": page, "total": total, "by_kind": by_kind, "sla_counts": sla_counts,
        "up_now": up_now, "down_now": down_now, "unknown_now": total - up_now - down_now,
        "up_pct": 100.0 * up_now / total if total else None, "down_pct": 100.0 * down_now / total if total else None,
        "overall": {"d1": uptime.overall(targets, "24h"), "d7": uptime.overall(targets, "7d"),
                    "d30": uptime.overall(targets, "30d")},
        "met_pct": 100.0 * sla_counts["met"] / with_data if with_data else None,
        "sla_donut": {"segments": [
            {"label": "Met", "value": sla_counts["met"], "color": stats.COLORS["online"]},
            {"label": "Breached", "value": sla_counts["breached"], "color": stats.COLORS["down"]},
            {"label": "No data", "value": sla_counts["nodata"], "color": stats.COLORS["unknown"]}],
            "center": {"value": str(total), "label": "Targets"}},
        "daily": daily, "has_daily": has_daily, "days": days,
        "kinds": uptime.KINDS, "kind_colors": uptime.KIND_COLOR, "sites": _sites(request), "statuses": Status.choices,
        "default_sla": DEFAULT_SLA, "default_sla_text": uptime.sla_text(DEFAULT_SLA), "sort_choices": SORT_CHOICES, "query": _query(request), "query_nodays": _query(request, "days"),
        "worst": [t for t in uptime.sort_targets(targets, "uptime") if t.up30 is not None][:5],
    })


@require("view")
def uptime_export(request):
    targets, _ = _uptime_targets(request)
    resp = HttpResponse(content_type="text/csv; charset=utf-8")
    resp["Content-Disposition"] = 'attachment; filename="uptime.csv"'
    w = csv.writer(resp)
    w.writerow(["type", "name", "target", "site", "status", "uptime_24h", "uptime_7d", "uptime_30d", "samples_30d",
                "sla_target", "sla_status", "last_checked"])
    fmt = lambda v: "" if v is None else f"{v:.3f}"  # noqa: E731
    for t in targets:
        w.writerow(_row([t.kind_label, t.name, t.address, t.site, t.status, fmt(t.up24), fmt(t.up7), fmt(t.up30),
                         t.samples.get("30d", (0, 0))[1], f"{t.sla:.3f}", t.sla_state,
                         t.last_checked_at.isoformat() if t.last_checked_at else ""]))
    return resp


def _target_site(kind, pk, user):
    """Site of a visible target, or None when the user cannot see it."""
    srcs = uptime.sources(user)
    if kind not in srcs:
        return None
    obj = srcs[kind].filter(pk=pk).first()
    if obj is None:
        return None
    return (obj.site_key if kind == "domain" else obj.site), str(obj)


@require("operate")
@require_POST
def sla_update(request):
    fallback = reverse("tcpcheck:uptime")
    form = SlaForm(request.POST)
    if not form.is_valid():
        errs = "; ".join(f"{k}: {' '.join(v)}" for k, v in form.errors.items())
        messages.error(request, f"SLA target not saved – {errs}")
        return redirect(_next(request, fallback))
    kind, pk, target = form.cleaned_data["kind"], form.cleaned_data["object_id"], form.cleaned_data["target"]
    found = _target_site(kind, pk, request.user)
    if found is None:
        messages.error(request, "That target does not exist or is not visible to you.")
        return redirect(_next(request, fallback))
    site, name = found
    if not services.can_manage(request.user, "operate", site):
        return _deny(request, fallback=fallback)
    obj, created = SlaTarget.objects.get_or_create(tenant_key=settings.LINKEDEYE_TENANT, kind=kind, object_id=pk,
                                                   defaults={"target": target})
    old = None if created else obj.target
    if not created:
        obj.target = target
        obj.save(update_fields=["target", "updated_at"])
    audit(request, "update", obj, target_type=kind, target_id=pk, target_name=name,
          sla=f"{target:.3f}", previous=None if old is None else f"{old:.3f}")
    messages.success(request, f"SLA target for “{name}” set to {target.normalize():f}%.")
    return redirect(_next(request, fallback))
