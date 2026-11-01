import re
from datetime import timedelta

from django.conf import settings
from django.contrib import messages
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST

from core.access import require, scope_by_site
from core.audit import audit

from .. import alerts as svc
from ..models import Alert
from .common import csv_response, paginate, perms, query_without_page

LABEL_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
RESOLVED_WINDOW_DAYS = 7
TABS = [("firing", "Firing"), ("resolved", "Recently resolved"), ("all", "All")]
SEVERITIES = [("critical", "Critical"), ("page", "Page"), ("warning", "Warning"), ("info", "Info")]


def _scoped(request):
    qs = Alert.objects.for_tenant()
    qs = scope_by_site(qs, request.user, field="site")
    site = request.GET.get("site", "")
    if site:
        qs = qs.filter(site=site)
    return qs


def parse_label(value):
    """'key=value' (or 'key:value') -> (key, value) when the key is a valid, non-nested label name."""
    if not value:
        return None
    for sep in ("=", ":"):
        if sep in value:
            k, v = value.split(sep, 1)
            k = k.strip()
            if LABEL_KEY.match(k) and "__" not in k:
                return k, v.strip()
    return None


def _filtered(request, base):
    tab = request.GET.get("tab", "firing")
    if tab not in dict(TABS):
        tab = "firing"
    qs = base
    if tab == "firing":
        qs = qs.firing()
    elif tab == "resolved":
        qs = qs.resolved().filter(last_received_at__gte=timezone.now() - timedelta(days=RESOLVED_WINDOW_DAYS))
    q = request.GET.get("q", "").strip()
    if q:
        qs = qs.filter(Q(alertname__icontains=q) | Q(instance__icontains=q) | Q(job__icontains=q)
                       | Q(summary__icontains=q) | Q(fingerprint__iexact=q))
    sev = request.GET.get("severity", "")
    if sev:
        qs = qs.filter(severity__iexact=sev)
    name = request.GET.get("alertname", "")
    if name:
        qs = qs.filter(alertname=name)
    ack = request.GET.get("ack", "")
    if ack == "no":
        qs = qs.filter(acknowledged_at__isnull=True)
    elif ack == "yes":
        qs = qs.filter(acknowledged_at__isnull=False)
    label = parse_label(request.GET.get("label", ""))
    if label:
        qs = qs.filter(**{f"labels__{label[0]}": label[1]})
    return tab, label, qs


@require("view")
def alert_list(request):
    base = _scoped(request)
    tab, label, qs = _filtered(request, base)
    if tab == "firing":
        qs = qs.order_by("acknowledged_at", "-starts_at", "-last_received_at")
    else:
        qs = qs.order_by("-last_received_at")
    qs = qs.select_related("acknowledged_by")
    if request.GET.get("format") == "csv":
        return csv_response("alertmanager-alerts.csv",
                            ["fingerprint", "status", "alertname", "severity", "instance", "job", "site", "summary",
                             "starts_at", "ends_at", "last_received_at", "acknowledged_by", "acknowledged_at", "labels"],
                            [[a.fingerprint, a.status, a.alertname, a.severity, a.instance, a.job, a.site, a.summary,
                              a.starts_at.isoformat() if a.starts_at else "", a.ends_at.isoformat() if a.ends_at else "",
                              a.last_received_at.isoformat(), a.acknowledged_by.get_username() if a.acknowledged_by else "",
                              a.acknowledged_at.isoformat() if a.acknowledged_at else "",
                              " ".join(f"{k}={v}" for k, v in sorted((a.labels or {}).items()))] for a in qs[:10000]])
    now = timezone.now()
    firing = base.firing()
    sev_counts = {s["severity"].lower(): s["n"] for s in firing.values("severity").annotate(n=Count("id"))}
    last = base.order_by("-last_received_at").values_list("last_received_at", flat=True).first()
    kpis = {
        "firing": firing.count(),
        "critical": sev_counts.get("critical", 0) + sev_counts.get("page", 0),
        "warning": sev_counts.get("warning", 0),
        "unacked": firing.filter(acknowledged_at__isnull=True).count(),
        "resolved24": base.resolved().filter(last_received_at__gte=now - timedelta(hours=24)).count(),
        "last": last,
    }
    tab_counts = {"firing": kpis["firing"],
                  "resolved": base.resolved().filter(last_received_at__gte=now - timedelta(days=RESOLVED_WINDOW_DAYS)).count(),
                  "all": base.count()}
    token_set = bool(getattr(settings, "ALERTMANAGER_WEBHOOK_TOKEN", ""))
    receiver_url = request.build_absolute_uri(reverse("telemetry:alertmanager_webhook"))
    ctx = {
        **perms(request), "page": paginate(request, qs), "tab": tab, "tabs": [(k, l, tab_counts[k]) for k, l in TABS],
        "label": label, "kpis": kpis, "severities": SEVERITIES,
        "alertnames": list(base.order_by().values_list("alertname", flat=True).distinct().order_by("alertname")[:200]),
        "top_alerts": list(firing.values("alertname").annotate(n=Count("id")).order_by("-n", "alertname")[:6]),
        "query": query_without_page(request), "filtered": any(request.GET.get(k) for k in ("q", "severity", "alertname", "ack", "label")),
        "token_set": token_set, "receiver_url": receiver_url,
        "next_url": request.get_full_path(),
    }
    return render(request, "telemetry/alerts.html", ctx)


@require("view")
def alert_detail(request, pk):
    a = get_object_or_404(_scoped(request).select_related("acknowledged_by"), pk=pk)
    from core.models import Event
    events = Event.objects.filter(fingerprint=a.event_fingerprint).order_by("-occurred_at")[:20]
    return render(request, "telemetry/alert_detail.html", {
        **perms(request), "a": a, "events": events, "incidents": _incidents(a),
        "labels": sorted((a.labels or {}).items()), "annotations": sorted((a.annotations or {}).items()),
    })


def _incidents(a):
    """Service Desk incidents opened for this alert, or None when the module is absent."""
    try:
        from django.apps import apps
        Ticket = apps.get_model("servicedesk", "Ticket")
    except (LookupError, ImportError):
        return None
    try:
        qs = Ticket.objects.filter(fingerprint=a.event_fingerprint)
        if hasattr(Ticket, "tenant_key"):
            qs = qs.filter(tenant_key=settings.LINKEDEYE_TENANT)
        rows = list(qs.order_by("-pk")[:5])
    except Exception:
        return None
    out = []
    for t in rows:
        url = ""
        try:
            url = t.get_absolute_url() if hasattr(t, "get_absolute_url") else reverse("servicedesk:detail", args=[t.number])
        except Exception:
            url = ""
        out.append({"number": getattr(t, "number", f"#{t.pk}"), "status": getattr(t, "status", ""),
                    "title": getattr(t, "title", ""), "priority": getattr(t, "priority", ""), "url": url})
    return out


def _redirect_back(request):
    nxt = request.POST.get("next", "")
    if nxt and url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()}, require_https=request.is_secure()):
        return redirect(nxt)
    return redirect("telemetry:alertmanager")


def _selected(request, pk=None):
    qs = _scoped(request)
    if pk is not None:
        return [get_object_or_404(qs, pk=pk)]
    ids = [i for i in request.POST.getlist("ids") if str(i).isdigit()][:500]
    return list(qs.filter(pk__in=ids))


@require("operate")
@require_POST
def acknowledge(request, pk=None):
    items = _selected(request, pk)
    if not items:
        messages.error(request, "Select at least one alert to acknowledge.")
        return _redirect_back(request)
    changed = svc.acknowledge(items, request.user)
    for a in changed:
        audit(request, "acknowledge", a, alertname=a.alertname, instance=a.instance, fingerprint=a.fingerprint)
    if changed:
        messages.success(request, f"Acknowledged {len(changed)} alert(s)." if len(changed) > 1 else f"Acknowledged “{changed[0]}”.")
    else:
        messages.warning(request, "The selected alert(s) were already acknowledged.")
    return _redirect_back(request)


@require("operate")
@require_POST
def unacknowledge(request, pk):
    items = _selected(request, pk)
    changed = svc.unacknowledge(items)
    for a in changed:
        audit(request, "unacknowledge", a, alertname=a.alertname, instance=a.instance, fingerprint=a.fingerprint)
    if changed:
        messages.success(request, f"Removed the acknowledgement from “{changed[0]}”.")
    else:
        messages.warning(request, "That alert was not acknowledged.")
    return _redirect_back(request)
