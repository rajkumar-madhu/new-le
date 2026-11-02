import csv
from datetime import timedelta

from django.conf import settings
from django.contrib import messages
from django.contrib.admin.views.decorators import staff_member_required
from django.core.paginator import Paginator
from django.db.models import Q
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from probes import runner

from . import stats
from .forms import UrlCheckForm
from .models import Status, UrlCheck, UrlResult


def _scope(request):
    return UrlCheck.objects.filter(tenant_key=settings.LINKEDEYE_TENANT)


def _filtered(request):
    qs = _scope(request)
    q = request.GET.get("q", "").strip()
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(url__icontains=q) | Q(tags__icontains=q))
    for param, field in (("site", "site"), ("status", "last_status"), ("type", "check_type")):
        v = request.GET.get(param)
        if v:
            qs = qs.filter(**{field: v})
    return qs


def _per_page(request, default=10):
    try:
        return max(5, min(100, int(request.GET.get("per", default))))
    except (TypeError, ValueError):
        return default


def _change(now, then):
    """Whole-number % change between two stored values, or None when there is nothing to compare with."""
    if now is None or not then:
        return None
    return round(100.0 * (now - then) / then)


def index(request, pk=None):
    scope = _scope(request)
    checks = list(scope.filter(enabled=True))
    counts = {s: sum(1 for c in checks if c.last_status == s) for s in Status.values}
    total = len(checks)
    pct = lambda n: (100.0 * n / total) if total else 0  # noqa: E731

    editing = get_object_or_404(scope, pk=pk) if pk else None
    if request.method == "POST":
        if not request.user.is_staff:
            messages.error(request, "Only operators can add or change URL checks.")
            return redirect("urlchecker:index")
        form = UrlCheckForm(request.POST, instance=editing)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.tenant_key = settings.LINKEDEYE_TENANT
            obj.save()
            runner.run_url_checks([obj])
            messages.success(request, f"Saved “{obj.name}” and ran its first check.")
            return redirect("urlchecker:index")
    else:
        form = UrlCheckForm(instance=editing)

    page = Paginator(_filtered(request), _per_page(request)).get_page(request.GET.get("page"))
    up24 = stats.uptime_map([c.pk for c in page], 24)
    for c in page:
        c.uptime24 = up24.get(c.pk)
    avg = stats.avg_response(checks)
    avg_prev = stats.avg_response(checks, hours=24, offset_hours=24)
    # Total URLs trend: enabled checks now vs the ones that already existed 7 days ago.
    before = sum(1 for c in checks if c.created_at <= timezone.now() - timedelta(days=7))
    all_events = request.GET.get("events") == "all"
    history = stats.daily_history(checks)
    history["xLabelEvery"] = 1
    history.update(stats.axis_scale(max((sum(s["values"][i] or 0 for s in history["series"]) for i in range(len(history["labels"]))), default=0)))
    ctx = {
        "page": page, "form": form, "editing": editing, "total": total, "counts": counts,
        "pct": {k: pct(v) for k, v in counts.items()}, "avg_response": avg,
        "total_delta": _change(total, before), "avg_delta": _change(avg, avg_prev),
        "uptime7": stats.overall_uptime(checks, 24 * 7),
        "donut": {"segments": [
            {"label": "Online", "value": counts["online"], "color": "#0f7a55"},
            {"label": "Down", "value": counts["down"], "color": "#d92d20"},
            {"label": "Degraded", "value": counts["degraded"], "color": "#e08a00"},
            {"label": "Unknown", "value": counts["unknown"], "color": "#d6cfc1"}],
            "center": {"value": str(total), "label": "Total URLs"}},
        "trend": stats.response_trend(checks), "history": history, "all_events": all_events,
        "events": UrlResult.objects.filter(url_check__tenant_key=settings.LINKEDEYE_TENANT).select_related("url_check")[:50 if all_events else 6],
        "sites": scope.order_by().values_list("site", flat=True).distinct(),
        "statuses": Status.choices, "types": UrlCheck.TYPES,
        "query": request.GET.copy(),
    }
    ctx["query"].pop("page", None)
    return render(request, "urlchecker/index.html", ctx)


@staff_member_required
@require_POST
def run_now(request, pk=None):
    qs = _scope(request).filter(enabled=True)
    items = [get_object_or_404(qs, pk=pk)] if pk else list(qs)
    results = runner.run_url_checks(items)
    summary = ", ".join(f"{c.name}: {s}" for c, s in zip(items, results)) if pk else f"Checked {len(items)} URL(s)"
    return JsonResponse({"checked": len(items), "summary": summary})


@staff_member_required
@require_POST
def delete(request, pk):
    obj = get_object_or_404(_scope(request), pk=pk)
    obj.delete()
    messages.success(request, f"Deleted “{obj.name}”.")
    return redirect("urlchecker:index")


def detail(request, pk):
    check = get_object_or_404(_scope(request), pk=pk)
    results = check.results.all()[:200]
    return render(request, "urlchecker/detail.html", {
        "check": check, "results": results[:50],
        "uptime24": stats.uptime_map([check.pk], 24).get(check.pk),
        "uptime7": stats.uptime_map([check.pk], 24 * 7).get(check.pk),
        "trend": stats.response_trend([check.pk]),
    })


def export_csv(request):
    resp = HttpResponse(content_type="text/csv")
    resp["Content-Disposition"] = 'attachment; filename="url-checks.csv"'
    w = csv.writer(resp)
    w.writerow(["name", "url", "type", "site", "status", "http_status", "response_ms", "last_checked", "message"])
    for c in _filtered(request):
        w.writerow([c.name, c.url, c.check_type, c.site, c.last_status, c.last_http_status or "",
                    "" if c.last_response_ms is None else round(c.last_response_ms), c.last_checked_at or "", c.last_error])
    return resp
