from datetime import datetime, time, timedelta

from django.conf import settings
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from core.access import can, require, visible_sites
from core.audit import audit
from core.models import Site

from . import analytics as an
from . import registry, scheduler
from .forms import ScheduleForm
from .models import ReportRun, ScheduledReport

PRESETS = [(1, "Last 24 hours"), (7, "Last 7 days"), (30, "Last 30 days"), (90, "Last 90 days")]
PREVIEW_ROWS = 200


def _site_names(user):
    names = list(Site.objects.filter(tenant_key=settings.LINKEDEYE_TENANT).order_by("name").values_list("name", flat=True))
    allowed = visible_sites(user)
    return names if allowed is None else [n for n in names if n in allowed]


def _site_param(request, sites):
    site = request.GET.get("site", "")
    return site if site in sites else ""


def _period(request, report):
    """(start, end, label, params). Snapshot reports with a horizon (SSL expiry) use `days` as that horizon."""
    now = timezone.now()
    if not report.uses_period:
        try:
            days = max(1, min(366, int(request.GET.get("days", 60))))
        except ValueError:
            days = 60
        return now - timedelta(days=days), now, f"{days} days", {"days": days}
    f, t = request.GET.get("from", ""), request.GET.get("to", "")
    if f or t:
        try:
            d_from = datetime.strptime(f, "%Y-%m-%d").date()
            d_to = datetime.strptime(t, "%Y-%m-%d").date() if t else timezone.localdate(now)
            if d_to < d_from or (d_to - d_from).days > 366:
                raise ValueError
            start = timezone.make_aware(datetime.combine(d_from, time.min))
            end = min(now, timezone.make_aware(datetime.combine(d_to + timedelta(days=1), time.min)))
            return start, end, f"{d_from:%d %b %Y} – {d_to:%d %b %Y}", {"from": f, "to": d_to.isoformat()}
        except ValueError:
            pass  # fall back to the preset below
    try:
        days = int(request.GET.get("days", 7))
    except ValueError:
        days = 7
    days = days if days in dict(PRESETS) else 7
    return now - timedelta(days=days), now, dict(PRESETS)[days], {"days": days}


def _report_or_404(user, key):
    report = registry.REPORTS.get(key)
    if report is None:
        raise Http404("Unknown report")
    if not report.allowed(user):
        raise PermissionDenied
    return report


def _can_manage(user, schedule):
    return can(user, "admin") or (schedule.owner_id == user.pk and can(user, "operate"))


@require("view")
def index(request):
    user = request.user
    groups = []
    for cat in registry.CATEGORIES:
        items = [r for r in registry.REPORTS.values() if r.category == cat and r.allowed(user)]
        if items:
            groups.append({"name": cat, "reports": items})
    schedules = ScheduledReport.objects.filter(tenant_key=settings.LINKEDEYE_TENANT).select_related("owner")
    runs = ReportRun.objects.filter(tenant_key=settings.LINKEDEYE_TENANT).select_related("schedule")
    if not can(user, "admin"):
        schedules = schedules.filter(owner=user)
        runs = runs.filter(requested_by=user) | runs.filter(schedule__owner=user)
    titles = {k: r.title for k, r in registry.REPORTS.items()}
    schedules = list(schedules)
    for s in schedules:
        s.report_title = titles.get(s.report_key, s.report_key)
        s.manageable = _can_manage(user, s)
    runs = list(runs.order_by("-created_at")[:15])
    for r in runs:
        r.report_title = titles.get(r.report_key, r.report_key)
    return render(request, "reports/index.html", {
        "groups": groups, "schedules": schedules, "runs": runs, "presets": PRESETS,
        "sites": _site_names(user), "can_operate": can(user, "operate"),
        "email_backend": settings.EMAIL_BACKEND.rsplit(".", 2)[-2] if "." in settings.EMAIL_BACKEND else settings.EMAIL_BACKEND,
        "report_count": sum(len(g["reports"]) for g in groups),
    })


@require("view")
def preview(request, key):
    report = _report_or_404(request.user, key)
    sites = _site_names(request.user)
    site = _site_param(request, sites)
    start, end, label, params = _period(request, report)
    if site:
        params["site"] = site
    rows, error = registry.generate(report, registry.Ctx(start, end, request.user, site), limit=PREVIEW_ROWS + 1)
    more = len(rows) > PREVIEW_ROWS
    return render(request, "reports/preview.html", {
        "report": report, "rows": rows[:PREVIEW_ROWS], "more": more, "error": error, "period_label": label,
        "params": params, "presets": PRESETS, "sites": sites, "site": site, "query": request.GET,
        "start": start, "end": end,
    })


@require("view")
def download(request, key):
    report = _report_or_404(request.user, key)
    site = _site_param(request, _site_names(request.user))
    start, end, label, _ = _period(request, report)
    rows, error = registry.generate(report, registry.Ctx(start, end, request.user, site))
    ReportRun.objects.create(report_key=key, channel="download", requested_by=request.user,
                             requested_by_name=request.user.get_username(), period_start=start, period_end=end,
                             site=site, rows=len(rows), status="failed" if error else ("ok" if rows else "empty"),
                             error=error)
    audit(request, "export", object_type="report", result="failed" if error else "ok",
          report=key, rows=len(rows), period=label, site=site or "all")
    if error:
        messages.error(request, error)
        return redirect("reports:preview", key=key)
    resp = HttpResponse(registry.to_csv(report, rows), content_type="text/csv; charset=utf-8")
    resp["Content-Disposition"] = f'attachment; filename="{key}-{timezone.localdate():%Y%m%d}.csv"'
    return resp


@require("operate")
def schedule_form(request, pk=None):
    schedule = None
    if pk is not None:
        schedule = get_object_or_404(ScheduledReport, pk=pk, tenant_key=settings.LINKEDEYE_TENANT)
        if not _can_manage(request.user, schedule):
            raise PermissionDenied
    sites = _site_names(request.user)
    initial = {"report_key": request.GET.get("report", "")} if schedule is None else None
    form = ScheduleForm(request.POST or None, instance=schedule, user=request.user, sites=sites, initial=initial)
    if request.method == "POST" and form.is_valid():
        obj = form.save(commit=False)
        if schedule is None:
            obj.owner = request.user
        obj.next_run_at = None  # recomputed from the (possibly changed) frequency and hour
        obj.save()
        audit(request, "create" if schedule is None else "update", obj, report=obj.report_key,
              frequency=obj.frequency, recipients=len(obj.recipient_list()))
        messages.success(request, f"Schedule “{obj.name}” saved." + (
            f" Next delivery {timezone.localtime(obj.next_run_at):%d %b %Y %H:%M}." if obj.next_run_at else " It is disabled."))
        return redirect("reports:index")
    return render(request, "reports/schedule_form.html", {"form": form, "schedule": schedule})


@require_POST
@require("operate")
def schedule_delete(request, pk):
    schedule = get_object_or_404(ScheduledReport, pk=pk, tenant_key=settings.LINKEDEYE_TENANT)
    if not _can_manage(request.user, schedule):
        raise PermissionDenied
    name = schedule.name
    audit(request, "delete", schedule, report=schedule.report_key)
    schedule.delete()
    messages.success(request, f"Schedule “{name}” deleted.")
    return redirect("reports:index")


@require_POST
@require("operate")
def schedule_send(request, pk):
    schedule = get_object_or_404(ScheduledReport, pk=pk, tenant_key=settings.LINKEDEYE_TENANT)
    if not _can_manage(request.user, schedule):
        raise PermissionDenied
    run = scheduler.deliver(schedule, requested_by=request.user)
    audit(request, "run", schedule, result="failed" if run.status == "failed" else "ok", rows=run.rows)
    if run.status == "failed":
        messages.error(request, f"Sending “{schedule.name}” failed: {run.error}")
    else:
        messages.success(request, f"“{schedule.name}” sent to {run.delivered_to} ({run.rows} rows).")
    return redirect("reports:index")


@require("view")
def analytics(request):
    user = request.user
    days = an.parse_range(request.GET.get("range"))
    sites = _site_names(user)
    site = _site_param(request, sites)
    w = an.Window(days)
    return render(request, "reports/analytics.html", {
        "ranges": an.RANGES, "days": days, "sites": sites, "site": site, "window": w,
        "sd": an.service_desk(user, w, site), "av": an.availability(user, w, site),
        "ev": an.events(user, w, site), "inv": an.inventory(user, site),
    })
