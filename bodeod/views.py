import calendar
import csv
from collections import defaultdict
from datetime import timedelta

from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.http import Http404, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_GET, require_http_methods, require_POST

from core.access import can, require, scope_by_site
from core.audit import audit
from core.models import Event

from . import services
from .forms import ChecklistItemForm, HolidayForm, HolidayUploadForm, ModeForm, SignOffForm
from .models import ChecklistItem, Holiday, Mode, Run, RunItem
from .services import IST, user_can

STATUS_META = {  # status -> (code, tone, label)
    "ok": (0, "ok", "OK"), "signed_off": (0, "ok", "Signed off"), "warning": (1, "warn", "WARN"),
    "critical": (2, "crit", "CRIT"), "unknown": (3, "mute", "UNKNOWN"), "pending": (5, "info", "PENDING"),
}
RUN_TONE = {"pass": "ok", "warn": "warn", "fail": "crit", "running": "info"}


# ------------------------------------------------------------------ helpers
def _per_page(request, default=20):
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


def _pk(value):
    """A primary key from a query/form parameter; anything that is not a positive integer is a 404 (not a 500)."""
    try:
        pk = int(str(value).strip())
    except (TypeError, ValueError):
        raise Http404("Invalid id")
    if pk <= 0:
        raise Http404("Invalid id")
    return pk


CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _cell(value):
    """Neutralise spreadsheet formulas in free-text CSV cells (CSV injection)."""
    if isinstance(value, str) and value.startswith(CSV_FORMULA_PREFIXES):
        return "'" + value
    return value


def _deny(request, text="You do not have permission to do that.", fallback=None):
    if _wants_json(request):
        return JsonResponse({"error": text}, status=403)
    messages.error(request, text)
    return redirect(_next(request, fallback or reverse("bodeod:status")))


def _perms(request):
    u = request.user
    return {"can_operate": can(u, "operate"), "can_configure": can(u, "configure"), "can_admin": can(u, "admin")}


def _modes(request):
    return scope_by_site(services.modes_qs(), request.user, field="site")


def _admin_modes(request):
    """Modes the user may reconfigure: admin on the mode's own site (global modes use the user's best role)."""
    return [m for m in _modes(request) if user_can(request.user, "admin", m.site)]


def _runs(request):
    return Run.objects.filter(mode__in=_modes(request)).select_related("mode")


def _decorate(result):
    code, tone, label = STATUS_META.get(result.status, STATUS_META["unknown"])
    result.code_num, result.tone, result.code_label = code, tone, label
    return result


class Live:
    """A checklist item with its live (stored) status for templates."""

    def __init__(self, item, status, detail, link=""):
        self.item, self.status, self.detail, self.link = item, status, detail, link
        self.code_num, self.tone, self.code_label = STATUS_META.get(status, STATUS_META["unknown"])
        self.name, self.kind, self.critical, self.ref_name = item.name, item.kind, item.critical, item.ref_name

    def get_kind_display(self):
        return self.item.get_kind_display()


def _live_rows(items, resolver=None):
    resolver = resolver or services.Resolver(items)
    out = []
    for it in items:
        st, detail = services.live_status(it, resolver)
        link = resolver.link(it.kind, it.ref_name) if it.automated and resolver.available(it.kind) else ""
        out.append(Live(it, st, detail, link))
    return out


def _run_counts(qs):
    return qs.annotate(
        n_total=Count("results"),
        n_ok=Count("results", filter=Q(results__status__in=["ok", "signed_off"])),
        n_warn=Count("results", filter=Q(results__status="warning")),
        n_crit=Count("results", filter=Q(results__status="critical")),
        n_unknown=Count("results", filter=Q(results__status="unknown")),
        n_pending=Count("results", filter=Q(results__status="pending")),
    ).order_by("-started_at", "-pk")


def _fmt_duration(seconds):
    if seconds is None:
        return "–"
    if seconds < 60:
        return f"{seconds:.1f} s"
    return f"{int(seconds // 60)} min {int(seconds % 60)} s"


# ------------------------------------------------------------------ status dashboard
@require_GET
def status(request):
    modes = list(_modes(request))
    today = services.today_ist()
    banner = services.trading_banner()
    cards, any_running, pending_total = [], False, 0
    latest_today = []
    for m in modes:
        run = services.latest_run(m)
        if run is not None:
            results = [_decorate(r) for r in run.results.all()]
            live = False
        else:
            results = _live_rows(list(m.items.filter(enabled=True)))
            live = True
        c = services.counts(results)
        if run is not None and run.trading_date == today:
            latest_today.append(run)
            pending_total += c["pending"]
        any_running = any_running or (run is not None and run.status == "running")
        cards.append({
            "mode": m, "run": run, "results": results, "live": live, "counts": c,
            "window": services.window_state(m, trading=banner["trading"]), "next": services.schedule_for(m),
            "can_run": user_can(request.user, "operate", m.site), "run_tone": RUN_TONE.get(run.status, "mute") if run else "mute",
            "run_today": run is not None and run.trading_date == today,
            "duration": _fmt_duration(run.duration_seconds) if run else "–",
        })
    today_runs = _runs(request).filter(trading_date=today)
    nexts = [c["next"] for c in cards if c["next"]]
    kpi = {
        "modes": sum(1 for m in modes if m.enabled), "modes_total": len(modes),
        "today_runs": today_runs.count(),
        "passed": sum(1 for r in latest_today if r.status == "pass"),
        "warned": sum(1 for r in latest_today if r.status == "warn"),
        "failed": sum(1 for r in latest_today if r.status == "fail"),
        "pending": pending_total,
        "next": min(nexts) if nexts else None,
    }
    recent = _run_counts(_runs(request))[:8]
    ctx = {"cards": cards, "banner": banner, "kpi": kpi, "recent": recent, "today": today,
           "refresh": 20 if any_running else 60, "run_tone": RUN_TONE, "phases": services.PHASES, **_perms(request)}
    return render(request, "bodeod/status.html", ctx)


@require_GET
def api_status(request):
    """JSON summary of every mode's latest run (for wallboards and integrations)."""
    out = []
    banner = services.trading_banner()
    for m in _modes(request):
        run = services.latest_run(m)
        entry = {"code": m.code, "name": m.name, "enabled": m.enabled, "window": m.window_label,
                 "window_state": services.window_state(m, trading=banner["trading"]), "latest_run": None}
        if run:
            entry["latest_run"] = {
                "id": run.pk, "trading_date": run.trading_date.isoformat(), "status": run.status,
                "started_at": run.started_at.isoformat(), "finished_at": run.finished_at.isoformat() if run.finished_at else None,
                "trigger": run.trigger, "summary": run.summary,
                "items": [{"name": r.name, "kind": r.kind, "status": r.status, "code": r.code, "critical": r.critical,
                           "detail": r.detail} for r in run.results.all()],
            }
        out.append(entry)
    return JsonResponse({"date": banner["date"].isoformat(), "trading_day": banner["trading"], "reason": banner["reason"],
                         "phase": banner["phase"]["key"], "modes": out})


# ------------------------------------------------------------------ mutations: runs
@require_POST
@require("operate")
def run_mode(request, pk):
    mode = get_object_or_404(_modes(request), pk=pk)
    if not user_can(request.user, "operate", mode.site):
        return _deny(request, f"You cannot run {mode.code} for {mode.site}.")
    if not mode.enabled:
        messages.error(request, f"{mode.code} is disabled. Enable it in the checklist editor first.")
        return redirect(_next(request, reverse("bodeod:status")))
    if not mode.items.filter(enabled=True).exists():
        messages.error(request, f"{mode.code} has no enabled checklist items.")
        return redirect(_next(request, reverse("bodeod:status")))
    refresh = request.POST.get("refresh", "1" if mode.refresh_checks else "0") == "1"
    try:
        run = services.start_run(mode, user=request.user, trigger="manual", refresh=refresh)
    except services.RunError as e:
        messages.error(request, str(e))
        return redirect(_next(request, reverse("bodeod:status")))
    audit(request, "run", run, mode=mode.code, status=run.status, refresh=refresh, trading_date=run.trading_date.isoformat())
    is_open, reason = services.trading_day(run.trading_date)
    text = f"{mode.code} run #{run.pk}: {run.get_status_display()} – {run.summary}."
    if not is_open:
        text += f" Note: today is not a trading day ({reason})."
    {"pass": messages.success, "warn": messages.warning, "fail": messages.error}.get(run.status, messages.info)(request, text)
    return redirect(_next(request, run.get_absolute_url()))


@require_POST
@require("operate")
def revalidate(request, pk):
    run = get_object_or_404(_runs(request), pk=pk)
    if not user_can(request.user, "operate", run.mode.site):
        return _deny(request, fallback=run.get_absolute_url())
    if not services.is_open_for_signoff(run):
        messages.error(request, "Only the latest run for today's trading date can be re-validated. Start a new run instead.")
        return redirect(_next(request, run.get_absolute_url()))
    previous = run.status
    try:
        services.revalidate(run, refresh=request.POST.get("refresh", "1") == "1")
    except services.RunError as e:
        messages.error(request, str(e))
        return redirect(_next(request, run.get_absolute_url()))
    audit(request, "revalidate", run, previous=previous, status=run.status)
    messages.success(request, f"Re-validated run #{run.pk}: {run.get_status_display()} – {run.summary}.")
    return redirect(_next(request, run.get_absolute_url()))


@require_POST
@require("operate")
def signoff(request, pk):
    result = get_object_or_404(RunItem.objects.filter(run__in=_runs(request)).select_related("run", "run__mode"), pk=pk)
    run = result.run
    if not user_can(request.user, "operate", run.mode.site):
        return _deny(request, fallback=run.get_absolute_url())
    form = SignOffForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Add a note describing what you verified before signing off.")
        return redirect(_next(request, run.get_absolute_url()))
    previous = run.status
    try:
        services.sign_off(result, request.user, form.cleaned_data["note"])
    except services.RunError as e:
        messages.error(request, str(e))
        return redirect(_next(request, run.get_absolute_url()))
    run.refresh_from_db()
    audit(request, "sign_off", result, run=run.pk, mode=run.mode.code, note=result.note, run_status=run.status,
          previous_run_status=previous)
    messages.success(request, f"Signed off “{result.name}”. {run.mode.code} run #{run.pk} is now {run.get_status_display()}.")
    return redirect(_next(request, run.get_absolute_url()))


# ------------------------------------------------------------------ key validation
@require_GET
def keys(request):
    modes = list(_modes(request))
    code = request.GET.get("mode", "")
    selected = [m for m in modes if m.code == code] if code else modes
    kind = request.GET.get("kind", "")
    q = request.GET.get("q", "").strip()
    state = request.GET.get("state", "")
    sections, totals = [], defaultdict(int)
    for m in selected:
        run = services.latest_run(m)
        by_item = {}
        if run is not None:
            by_item = {r.item_id: _decorate(r) for r in run.results.all() if r.item_id}
        items = list(m.items.all())
        if kind:
            items = [i for i in items if i.kind == kind]
        if q:
            ql = q.lower()
            items = [i for i in items if ql in i.name.lower() or ql in i.ref_name.lower()]
        rows = []
        for live in _live_rows(items):
            live.result = by_item.get(live.item.pk)
            # the item's current state: its sign-off / result in today's run for manual items, else live
            current = live.result.status if (live.item.kind == "manual" and live.result and run.trading_date == services.today_ist()) else live.status
            live.current = current
            live.current_meta = STATUS_META.get(current, STATUS_META["unknown"])
            if not live.item.enabled:
                live.current = "disabled"
            if state and live.current != state:
                continue
            rows.append(live)
            if live.item.enabled:
                totals["total"] += 1
                totals[current] += 1
        open_signoff = run is not None and services.is_open_for_signoff(run)
        sections.append({"mode": m, "run": run, "rows": rows, "open_signoff": open_signoff,
                         "can_operate": user_can(request.user, "operate", m.site),
                         "run_tone": RUN_TONE.get(run.status, "mute") if run else "mute"})
    totals = {k: totals.get(k, 0) for k in ("total", "ok", "signed_off", "warning", "critical", "unknown", "pending")}
    totals["done"] = totals["ok"] + totals["signed_off"]
    ctx = {"modes": modes, "sections": sections, "code": code, "kinds": ChecklistItem.KINDS, "kind": kind, "q": q,
           "state": state, "totals": totals, "states": [("ok", "OK"), ("warning", "Warning"), ("critical", "Critical"),
                                                         ("unknown", "Unknown"), ("pending", "Pending"), ("signed_off", "Signed off")],
           "today": services.today_ist(), "query": _query(request), **_perms(request)}
    return render(request, "bodeod/keys.html", ctx)


# ------------------------------------------------------------------ history
def _history_filtered(request):
    qs = _runs(request)
    g = request.GET
    if g.get("mode"):
        qs = qs.filter(mode__code=g["mode"])
    if g.get("status"):
        qs = qs.filter(status=g["status"])
    if g.get("trigger"):
        qs = qs.filter(trigger=g["trigger"])
    d_from, d_to = services.parse_date(g.get("from", "")), services.parse_date(g.get("to", ""))
    if d_from:
        qs = qs.filter(trading_date__gte=d_from)
    if d_to:
        qs = qs.filter(trading_date__lte=d_to)
    q = g.get("q", "").strip()
    if q:
        matching = RunItem.objects.filter(Q(name__icontains=q) | Q(ref_name__icontains=q) | Q(note__icontains=q)).values("run_id")
        qs = qs.filter(Q(triggered_by_name__icontains=q) | Q(summary__icontains=q) | Q(pk__in=matching))
    return qs, d_from, d_to


def _history_chart(runs_qs, days=14):
    today = services.today_ist()
    start = today - timedelta(days=days - 1)
    per = defaultdict(lambda: {"pass": 0, "warn": 0, "fail": 0})
    for d, st in runs_qs.filter(trading_date__gte=start, trading_date__lte=today).exclude(status="running").values_list("trading_date", "status"):
        per[d][st] += 1
    labels, p, w, f = [], [], [], []
    for i in range(days):
        d = start + timedelta(days=i)
        labels.append(d.strftime("%d %b"))
        p.append(per[d]["pass"] or None)
        w.append(per[d]["warn"] or None)
        f.append(per[d]["fail"] or None)
    return {"labels": labels, "xLabelEvery": 2, "series": [
        {"name": "Pass", "color": "#16a34a", "values": p},
        {"name": "Warning", "color": "#f59e0b", "values": w},
        {"name": "Fail", "color": "#dc2626", "values": f}]}


@require_GET
def history(request):
    qs, d_from, d_to = _history_filtered(request)
    stats = list(qs.order_by().values_list("status", "started_at", "finished_at")[:5000])
    finished = [s for s in stats if s[0] != "running"]
    durations = [(fin - st).total_seconds() for _, st, fin in finished if fin]
    k = {"total": len(stats), "pass": sum(1 for s in stats if s[0] == "pass"), "warn": sum(1 for s in stats if s[0] == "warn"),
         "fail": sum(1 for s in stats if s[0] == "fail"),
         "avg": _fmt_duration(sum(durations) / len(durations)) if durations else "–"}
    k["pass_rate"] = (100.0 * k["pass"] / len(finished)) if finished else None
    page = Paginator(_run_counts(qs), _per_page(request)).get_page(request.GET.get("page"))
    for r in page:
        r.tone = RUN_TONE.get(r.status, "mute")
        r.duration = _fmt_duration(r.duration_seconds)
    chart = _history_chart(_runs(request))
    ctx = {"page": page, "k": k, "modes": _modes(request), "statuses": Run.STATUSES, "triggers": Run.TRIGGERS,
           "chart": chart, "has_chart": any(v for s in chart["series"] for v in s["values"]),
           "query": _query(request), "d_from": d_from, "d_to": d_to, **_perms(request)}
    return render(request, "bodeod/history.html", ctx)


@require_GET
def history_export(request):
    qs, _f, _t = _history_filtered(request)
    resp = HttpResponse(content_type="text/csv")
    resp["Content-Disposition"] = 'attachment; filename="bod-eod-runs.csv"'
    w = csv.writer(resp)
    w.writerow(["run", "mode", "trading_date", "started_at_ist", "finished_at_ist", "duration_s", "trigger", "triggered_by",
                "status", "ok", "warning", "critical", "unknown", "pending", "summary"])
    for r in _run_counts(qs)[:10000]:
        w.writerow([r.pk, r.mode.code, r.trading_date.isoformat(), timezone.localtime(r.started_at, IST).strftime("%Y-%m-%d %H:%M:%S"),
                    timezone.localtime(r.finished_at, IST).strftime("%Y-%m-%d %H:%M:%S") if r.finished_at else "",
                    "" if r.duration_seconds is None else round(r.duration_seconds, 1), r.trigger, _cell(r.by_label), r.status,
                    r.n_ok, r.n_warn, r.n_crit, r.n_unknown, r.n_pending, _cell(r.summary)])
    return resp


@require_GET
def detail(request, pk):
    run = get_object_or_404(_runs(request), pk=pk)
    results = [_decorate(r) for r in run.results.select_related("item")]
    resolver = services.Resolver(results)
    for r in results:
        r.link = resolver.link(r.kind, r.ref_name) if r.automated and resolver.available(r.kind) else ""
        r.instructions = r.item.instructions if r.item_id else ""
    timeline = [{"at": run.started_at, "tone": "info", "icon": "play",
                 "text": f"Run started by {run.by_label}" + (" (checks re-run first)" if run.refreshed else "")}]
    for r in results:
        if r.signed_off_at:
            timeline.append({"at": r.signed_off_at, "tone": "ok", "icon": "check",
                             "text": f"“{r.name}” signed off by {r.signed_off_by_name}" + (f": {r.note}" if r.note else "")
                             + (" (carried forward from an earlier run today)" if r.signed_off_at < run.started_at else "")})
        elif r.checked_at and r.automated:
            timeline.append({"at": r.checked_at, "tone": r.tone, "icon": "radar",
                             "text": f"“{r.name}” {r.code_label} – {r.detail}"})
    events = list(Event.objects.filter(source="bodeod", object_type="bodeod.run", object_id=str(run.pk)).order_by("occurred_at"))
    for e in events:
        tone = {"critical": "crit", "warning": "warn", "ok": "ok"}.get(e.severity, "info")
        timeline.append({"at": e.occurred_at, "tone": tone, "icon": "bell", "text": f"Event: {e.title}"})
    if run.finished_at and not events:
        timeline.append({"at": run.finished_at, "tone": RUN_TONE.get(run.status, "mute"), "icon": "check-circle",
                         "text": f"Run finished: {run.get_status_display()}"})
    timeline.sort(key=lambda t: t["at"])
    is_open = services.is_open_for_signoff(run)
    ctx = {"run": run, "results": results, "crumb": f"Run #{run.pk}", "counts": services.counts(results), "timeline": timeline,
           "run_tone": RUN_TONE.get(run.status, "mute"), "duration": _fmt_duration(run.duration_seconds),
           "is_open": is_open, "can_run": user_can(request.user, "operate", run.mode.site),
           "trading": services.trading_day(run.trading_date), **_perms(request)}
    return render(request, "bodeod/detail.html", ctx)


# ------------------------------------------------------------------ checklist editor
def _ref_suggestions():
    out = {}
    for kind, (app_label, model_name, field_name) in services.REF_MODELS.items():
        M = services._model(app_label, model_name)
        found = services.query_refs(M, field_name) if M is not None else None
        if found:
            out[kind] = list(found)
    return out


def _checklist_sections(request, modes):
    return [{"mode": m, "rows": _live_rows(list(m.items.all())), "can_edit": user_can(request.user, "admin", m.site)}
            for m in modes]


@require_http_methods(["GET", "POST"])
def checklist(request):
    modes = list(_modes(request))
    admin_modes = _admin_modes(request)
    admin_pks = [m.pk for m in admin_modes]
    can_admin = bool(admin_modes) or can(request.user, "admin")
    editing = None
    if request.GET.get("edit"):
        editing = get_object_or_404(ChecklistItem, pk=_pk(request.GET["edit"]), mode__in=modes)
        if editing.mode_id not in admin_pks:
            editing = None
            messages.error(request, "You cannot change the checklist of that mode.")
    if request.method == "POST":
        if not can_admin:
            return _deny(request, "Only administrators can change the checklist.", reverse("bodeod:checklist"))
        pk = request.POST.get("pk")
        editing = get_object_or_404(ChecklistItem, pk=_pk(pk), mode__in=modes) if pk else None
        if editing is not None and editing.mode_id not in admin_pks:
            return _deny(request, f"Only administrators of {editing.mode.site} can change the {editing.mode.code} checklist.",
                         reverse("bodeod:checklist"))
        form = ChecklistItemForm(request.POST, instance=editing)
        form.fields["mode"].queryset = Mode.objects.filter(pk__in=admin_pks)
        if form.is_valid():
            item = form.save()
            audit(request, "update" if editing else "create", item, mode=item.mode.code, kind=item.kind,
                  ref_name=item.ref_name, critical=item.critical, enabled=item.enabled)
            messages.success(request, f"Saved checklist item “{item.name}” ({item.mode.code}).")
            if item.automated:
                st, detail = services.live_status(item)
                if st == "unknown":
                    messages.warning(request, f"“{item.name}”: {detail}. It will report UNKNOWN until that is fixed.")
            return redirect(reverse("bodeod:checklist") + f"?mode={item.mode.code}#mode-{item.mode.code}")
    else:
        initial = {}
        if not editing:
            m = next((m for m in admin_modes if m.code == request.GET.get("mode")), admin_modes[0] if admin_modes else None)
            if m is not None:
                last = m.items.order_by("-order").first()
                initial = {"mode": m, "order": (last.order + 10) if last else 10}
        form = ChecklistItemForm(instance=editing, initial=initial)
        form.fields["mode"].queryset = Mode.objects.filter(pk__in=admin_pks)
    mode_edit = None
    if request.GET.get("mode_edit"):
        mode_edit = get_object_or_404(_modes(request), pk=_pk(request.GET["mode_edit"]))
        if mode_edit.pk not in admin_pks:
            mode_edit = None
            messages.error(request, "You cannot change the settings of that mode.")
    mode_form = ModeForm(instance=mode_edit, user=request.user) if (mode_edit or request.GET.get("mode_new")) else None
    existing = {m.code for m in services.modes_qs()}
    ctx = {"sections": _checklist_sections(request, modes), "form": form, "editing": editing, "mode_form": mode_form,
           "mode_edit": mode_edit, "can_add_mode": can_admin and len(existing) < len(Mode.CODES), "refs": _ref_suggestions(),
           "can_edit_items": bool(admin_modes),
           "show_form": can_admin and (editing is not None or request.method == "POST" or request.GET.get("new")),
           **_perms(request)}
    return render(request, "bodeod/checklist.html", ctx)


@require_POST
@require("admin")
def mode_save(request):
    pk = request.POST.get("pk")
    instance = get_object_or_404(_modes(request), pk=_pk(pk)) if pk else None
    if instance is not None and not user_can(request.user, "admin", instance.site):
        return _deny(request, f"Only administrators of {instance.site} can change the {instance.code} mode.",
                     reverse("bodeod:checklist"))
    form = ModeForm(request.POST, instance=instance, user=request.user)
    if form.is_valid():
        mode = form.save(commit=False)
        if not instance:
            mode.tenant_key = services.tenant()
        mode.save()
        audit(request, "update" if instance else "create", mode, code=mode.code, window=mode.window_label,
              auto_run_time=mode.auto_run_time.strftime("%H:%M") if mode.auto_run_time else "", enabled=mode.enabled)
        messages.success(request, f"Saved mode {mode.code} ({mode.window_label}).")
        return redirect(reverse("bodeod:checklist") + f"#mode-{mode.code}")
    modes = list(_modes(request))
    admin_pks = [m.pk for m in _admin_modes(request)]
    item_form = ChecklistItemForm()
    item_form.fields["mode"].queryset = Mode.objects.filter(pk__in=admin_pks)
    existing = {m.code for m in services.modes_qs()}
    messages.error(request, "Please correct the mode settings below.")
    return render(request, "bodeod/checklist.html", {
        "sections": _checklist_sections(request, modes), "form": item_form, "editing": None, "mode_form": form,
        "mode_edit": instance, "can_add_mode": len(existing) < len(Mode.CODES), "refs": _ref_suggestions(),
        "can_edit_items": bool(admin_pks), "show_form": False, **_perms(request)},
        status=400)


@require_POST
@require("admin")
def item_delete(request, pk):
    item = get_object_or_404(ChecklistItem, pk=pk, mode__in=_modes(request))
    if not user_can(request.user, "admin", item.mode.site):
        return _deny(request, f"Only administrators of {item.mode.site} can change the {item.mode.code} checklist.",
                     reverse("bodeod:checklist"))
    code, name = item.mode.code, item.name
    audit(request, "delete", item, mode=code, kind=item.kind, ref_name=item.ref_name)
    item.delete()
    messages.success(request, f"Deleted checklist item “{name}” from {code}. Past run results keep their copy.")
    return redirect(reverse("bodeod:checklist") + f"#mode-{code}")


@require_POST
@require("admin")
def item_move(request, pk):
    item = get_object_or_404(ChecklistItem, pk=pk, mode__in=_modes(request))
    if not user_can(request.user, "admin", item.mode.site):
        return _deny(request, f"Only administrators of {item.mode.site} can change the {item.mode.code} checklist.",
                     reverse("bodeod:checklist"))
    direction = request.POST.get("direction")
    if direction not in ("up", "down"):
        messages.error(request, "Choose whether to move the item up or down.")
        return redirect(reverse("bodeod:checklist") + f"#mode-{item.mode.code}")
    items = list(item.mode.items.order_by("order", "pk"))
    i = items.index(item)
    j = i - 1 if direction == "up" else i + 1
    if 0 <= j < len(items):
        items[i], items[j] = items[j], items[i]
        for n, it in enumerate(items, start=1):
            if it.order != n * 10:
                it.order = n * 10
                it.save(update_fields=["order", "updated_at"])
        audit(request, "reorder", item, mode=item.mode.code, direction=direction, order=item.order)
        messages.success(request, f"Moved “{item.name}” {'up' if j < i else 'down'}.")
    return redirect(reverse("bodeod:checklist") + f"#mode-{item.mode.code}")


# ------------------------------------------------------------------ holidays
def _year(request):
    try:
        y = int(request.GET.get("year") or services.today_ist().year)
    except ValueError:
        y = services.today_ist().year
    return max(2000, min(2100, y))


def _holiday_qs(request, year):
    start, end = services.year_bounds(year)
    qs = Holiday.objects.filter(tenant_key=services.tenant(), date__gte=start, date__lte=end)
    ex = request.GET.get("exchange", "")
    if ex:
        qs = qs.filter(exchange=ex)
    return qs.order_by("date", "exchange")


def _months(year, holidays):
    by_day = defaultdict(list)
    for h in holidays:
        by_day[h.date].append(h)
    cal = calendar.Calendar(firstweekday=0)
    today = services.today_ist()
    months = []
    for m in range(1, 13):
        weeks = []
        for week in cal.monthdatescalendar(year, m):
            days = []
            for d in week:
                hs = by_day.get(d, []) if d.month == m else []
                days.append({"date": d, "in_month": d.month == m, "weekend": d.weekday() >= 5, "holidays": hs,
                             "today": d == today, "title": "; ".join(f"{h.exchange}: {h.description}" for h in hs)})
            weeks.append(days)
        months.append({"name": calendar.month_name[m], "weeks": weeks, "count": sum(1 for d, hs in by_day.items() if d.month == m and d.year == year)})
    return months


@require_http_methods(["GET", "POST"])
def holidays(request):
    year = _year(request)
    can_configure = can(request.user, "configure")
    form = HolidayForm(initial={"exchange": "NSE"})
    if request.method == "POST":
        if not can_configure:
            return _deny(request, "Only operators and administrators can add holidays.", reverse("bodeod:holidays"))
        form = HolidayForm(request.POST)
        if form.is_valid():
            h = form.save(commit=False)
            h.tenant_key, h.source = services.tenant(), "manual"
            h.save()
            audit(request, "create", h, exchange=h.exchange, date=h.date.isoformat(), description=h.description)
            messages.success(request, f"Added holiday {h.date:%d %b %Y} ({h.exchange}): {h.description}.")
            return redirect(reverse("bodeod:holidays") + f"?year={h.date.year}")
    hs = list(_holiday_qs(request, year))
    today = services.today_ist()
    upcoming = Holiday.objects.filter(tenant_key=services.tenant(), date__gte=today).order_by("date")[:5]
    weekdays = [h for h in hs if h.date.weekday() < 5]
    ctx = {"year": year, "holidays": hs, "months": _months(year, hs), "form": form, "upload_form": HolidayUploadForm(),
           "exchanges": Holiday.EXCHANGES, "exchange": request.GET.get("exchange", ""), "upcoming": upcoming,
           "k": {"total": len(hs), "weekday": len(weekdays), "examples": sum(1 for h in hs if h.source == "example"),
                 "trading_closed": len({h.date for h in weekdays if h.exchange in services.TRADING_EXCHANGES})},
           "banner": services.trading_banner(), "phases": services.PHASES, "query": _query(request), "weekday_names": ["Mo", "Tu", "We", "Th", "Fr", "Sa", "Su"],
           **_perms(request)}
    return render(request, "bodeod/holidays.html", ctx, status=400 if request.method == "POST" else 200)


@require_POST
@require("configure")
def holiday_upload(request):
    form = HolidayUploadForm(request.POST, request.FILES)
    if not form.is_valid():
        for errs in form.errors.values():
            for e in errs:
                messages.error(request, e)
        return redirect("bodeod:holidays")
    parsed = services.parse_holidays_csv(form.cleaned_data["file"].read(), form.cleaned_data["default_exchange"])
    if not parsed.rows:
        messages.error(request, "No holidays imported. " + " ".join(parsed.errors[:5]))
        return redirect("bodeod:holidays")
    created, updated = services.import_holidays(parsed.rows)
    audit(request, "import", None, object_type="bodeod.holiday", created=created, updated=updated,
          skipped=len(parsed.errors), filename=form.cleaned_data["file"].name[:100])
    messages.success(request, f"Imported holidays: {created} added, {updated} updated.")
    if parsed.errors:
        more = f" (+{len(parsed.errors) - 5} more)" if len(parsed.errors) > 5 else ""
        messages.warning(request, f"Skipped {len(parsed.errors)} row(s): " + "; ".join(parsed.errors[:5]) + more)
    years = sorted({d.year for _e, d, _desc in parsed.rows})
    return redirect(reverse("bodeod:holidays") + f"?year={years[0]}")


@require_POST
@require("admin")
def holiday_delete(request, pk):
    h = get_object_or_404(Holiday, pk=pk, tenant_key=services.tenant())
    audit(request, "delete", h, exchange=h.exchange, date=h.date.isoformat(), description=h.description)
    year = h.date.year
    text = f"Deleted holiday {h.date:%d %b %Y} ({h.exchange}): {h.description}."
    h.delete()
    messages.success(request, text)
    return redirect(_next(request, reverse("bodeod:holidays") + f"?year={year}"))


@require_GET
def holidays_export(request):
    year = _year(request)
    resp = HttpResponse(content_type="text/csv")
    resp["Content-Disposition"] = f'attachment; filename="holidays-{year}.csv"'
    w = csv.writer(resp)
    w.writerow(["date", "exchange", "description", "weekday", "source"])
    for h in _holiday_qs(request, year):
        w.writerow([h.date.isoformat(), h.exchange, _cell(h.description), h.date.strftime("%A"), h.source])
    return resp

