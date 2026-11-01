from urllib.parse import urlencode

from django.conf import settings
from django.contrib import messages
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_POST

from core import prometheus
from core.access import can, require
from core.audit import audit

from .. import explorer as svc
from ..models import SavedQuery
from .common import perms, prom_context


def _visible_saved(user):
    return (SavedQuery.objects.filter(tenant_key=settings.LINKEDEYE_TENANT)
            .filter(Q(owner=user) | Q(shared=True)).select_related("owner").order_by("name"))


@require("view")
def explorer(request):
    ctx = {**prom_context(), **perms(request), "error": "", "policy_error": "", "result": None, "notes": [],
           "ranges": svc.RANGES, "examples": svc.EXAMPLES,
           "limits": {"chars": svc.MAX_QUERY_CHARS, "points": svc.MAX_POINTS, "series": svc.MAX_SERIES,
                      "timeout": getattr(settings, "PROMETHEUS_TIMEOUT", None)}}
    q = request.GET.get("expr", "")
    range_key = request.GET.get("range", svc.DEFAULT_RANGE)
    step_raw = request.GET.get("step", "").strip()
    loaded = None
    if request.GET.get("saved"):
        loaded = _visible_saved(request.user).filter(pk=request.GET.get("saved")).first() if request.GET["saved"].isdigit() else None
        if loaded is None:
            messages.error(request, "That saved query does not exist or is not shared with you.")
        elif not q:
            q, range_key = loaded.promql, loaded.range_key
    if range_key not in svc.RANGE_SECONDS:
        range_key = svc.DEFAULT_RANGE
    ctx.update({"q": q, "range_key": range_key, "step_raw": step_raw, "loaded": loaded})
    if q.strip():
        step = None
        if step_raw:
            step = svc.parse_duration(step_raw)
            if step is None:
                ctx["policy_error"] = "Step must be a duration such as 30s, 5m or 1h."
        if not ctx["policy_error"]:
            try:
                promql, seconds, step, notes = svc.check(q, svc.RANGE_SECONDS[range_key], step)
                ctx["notes"] = notes
                ctx["step"] = step
                ctx["points"] = seconds // step + 1
            except svc.PolicyError as e:
                ctx["policy_error"] = str(e)
        if not ctx["policy_error"] and ctx["prom_configured"]:
            try:
                ctx["result"] = svc.run(promql, seconds, step)
                ctx["notes"] = ctx["notes"] + ctx["result"]["notes"]
            except prometheus.PrometheusError as e:
                ctx["error"] = str(e)
    ctx["saved"] = list(_visible_saved(request.user))
    return render(request, "telemetry/explorer.html", ctx)


def _back(q="", range_key="", saved=None):
    params = {}
    if saved is not None:
        params["saved"] = saved.pk
    elif q:
        params.update({"expr": q, "range": range_key})
    return redirect(reverse("telemetry:explorer") + ("?" + urlencode(params) if params else ""))


@require("operate")
@require_POST
def save_query(request):
    name = request.POST.get("name", "").strip()
    promql = request.POST.get("promql", "").strip()
    range_key = request.POST.get("range", svc.DEFAULT_RANGE)
    if range_key not in svc.RANGE_SECONDS:
        range_key = svc.DEFAULT_RANGE
    description = request.POST.get("description", "").strip()[:300]
    shared = request.POST.get("shared") in ("on", "1", "true")
    if not name or len(name) > 120:
        messages.error(request, "Give the query a name (up to 120 characters).")
        return _back(promql, range_key)
    try:
        promql, *_ = svc.check(promql, svc.RANGE_SECONDS[range_key])
    except svc.PolicyError as e:
        messages.error(request, f"Not saved: {e}")
        return _back(promql, range_key)
    obj, created = SavedQuery.objects.update_or_create(
        tenant_key=settings.LINKEDEYE_TENANT, owner=request.user, name=name,
        defaults={"promql": promql, "range_key": range_key, "description": description, "shared": shared})
    audit(request, "create" if created else "update", obj, name=name, promql=promql[:500], shared=shared, range=range_key)
    messages.success(request, f"{'Saved' if created else 'Updated'} query “{name}”.")
    return _back(saved=obj)


@require("operate")
@require_POST
def delete_query(request, pk):
    obj = get_object_or_404(SavedQuery, pk=pk, tenant_key=settings.LINKEDEYE_TENANT)
    if obj.owner_id != request.user.pk and not can(request.user, "admin"):
        messages.error(request, "Only the owner or an administrator can delete this query.")
        return redirect("telemetry:explorer")
    name = obj.name
    audit(request, "delete", obj, name=name, promql=obj.promql[:500])
    obj.delete()
    messages.success(request, f"Deleted saved query “{name}”.")
    return redirect("telemetry:explorer")
