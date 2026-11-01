import csv
import json
import math
from collections import defaultdict
from datetime import timedelta
from urllib.parse import urlsplit

from django.conf import settings
from django.contrib import messages
from django.contrib.admin.views.decorators import staff_member_required
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.db import IntegrityError
from django.db.models import Count, Q
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_http_methods, require_POST

from core.access import can, require, scope_by_site
from core.audit import audit
from probes import checks, runner
from urlchecker.models import UrlCheck

from .forms import DomainForm
from .models import Domain, DomainCheck

HEALTHY_SSL = ("Valid",)
SSL_STATES = ["Valid", "Expiring", "Expired", "Invalid", "Unreachable", "Unknown"]
DNS_STATES = ["Resolved", "Failed", "Unknown"]
SORTS = {"status": ("status", "hostname"), "-status": ("-status", "hostname"), "hostname": ("hostname",),
         "-hostname": ("-hostname",), "response": ("response_ms",), "-response": ("-response_ms",),
         "expiry": ("ssl_expires_at",), "-expiry": ("-ssl_expires_at",), "checked": ("last_checked_at",),
         "-checked": ("-last_checked_at",)}
# selectable chart windows: value -> (label, total minutes, bucket minutes, label every n buckets, label format)
RESP_RANGES = {"6": ("Last 6 hours", 360, 15, 4, "%H:%M"), "24": ("Last 24 hours", 1440, 30, 8, "%H:%M"),
               "168": ("Last 7 days", 10080, 180, 8, "%b %d")}
UP_RANGES = {"7": ("Last 7 days", 7, 1), "14": ("Last 14 days", 14, 2), "30": ("Last 30 days", 30, 5)}


def _scope(request=None):
    """Domains of this tenant; with a request, limited to the sites the user may see ("All Sites" stays visible)."""
    qs = Domain.objects.filter(tenant_key=settings.LINKEDEYE_TENANT)
    if request is not None:
        qs = scope_by_site(qs, request.user, field="site_key")
    return qs


def _render(request, template, context):
    context.setdefault("can_operate", can(request.user, "operate"))
    return render(request, template, context)


def _uptime(domain_ids, hours, end=None):
    end = end or timezone.now()
    since = end - timedelta(hours=hours)
    rows = (DomainCheck.objects.filter(domain_id__in=domain_ids, checked_at__gte=since, checked_at__lt=end).values("domain_id")
            .annotate(total=Count("id"), up=Count("id", filter=Q(up=True))))
    return {r["domain_id"]: 100.0 * r["up"] / r["total"] for r in rows if r["total"]}


def _mean(values):
    values = [v for v in values if v is not None]
    return sum(values) / len(values) if values else None


def _change(cur, prev):
    """Relative change in percent, or None when there is nothing to compare with."""
    if cur is None or not prev:
        return None
    return round(100.0 * (cur - prev) / prev, 1)


def _per_page(request, default=10):
    try:
        return max(5, min(100, int(request.GET.get("per", default))))
    except (TypeError, ValueError):
        return default


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _query(request, *drop):
    q = request.GET.copy()
    for k in ("page", "selected", "format") + drop:
        q.pop(k, None)
    return q


def _filter(qs, request):
    """Filters shared by the overview table, the domain list and the CSV export."""
    q = request.GET.get("q", "").strip()
    if q:
        qs = qs.filter(Q(hostname__icontains=q) | Q(description__icontains=q))
    for param, field in (("status", "status"), ("ssl", "ssl_status"), ("dns", "dns_status"), ("group", "group"),
                         ("site", "site_key"), ("type", "domain_type")):
        if request.GET.get(param):
            qs = qs.filter(**{field: request.GET[param]})
    if request.GET.get("active") in ("1", "0"):
        qs = qs.filter(is_active=request.GET["active"] == "1")
    return qs


def _hostname_of(url):
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def associated_services(domain):
    """URL checks whose URL host is the domain or one of its sub-domains."""
    host = domain.hostname.lower()
    out = []
    for c in UrlCheck.objects.filter(tenant_key=settings.LINKEDEYE_TENANT, url__icontains=host):
        h = _hostname_of(c.url)
        if h == host or h.endswith("." + host):
            parts = urlsplit(c.url)
            try:
                port = parts.port
            except ValueError:
                port = None
            c.port = port or (443 if parts.scheme == "https" else 80)
            c.scheme = parts.scheme.upper()
            out.append(c)
    return out


# ------------------------------------------------------------------ overview (monitoring view)
def overview(request):
    if request.GET.get("format") == "csv":
        return export_csv(request)
    scope = _scope(request).filter(is_active=True)
    domains = list(scope)
    total = len(domains)
    down = [d for d in domains if d.status == "down"]
    expiring = [d for d in domains if d.ssl_status in ("Expiring", "Expired")]
    paused = [d for d in domains if not d.monitor_enabled]
    healthy = [d for d in domains if d.status == "up" and d.dns_status == "Resolved" and d.ssl_status in HEALTHY_SSL]
    ids = [d.pk for d in domains]
    now = timezone.now()

    # response time: selectable window, aligned to whole hours so the axis shows round times
    resp_key = request.GET.get("resp_range") if request.GET.get("resp_range") in RESP_RANGES else "24"
    resp_label, minutes, bucket, every, fmt = RESP_RANGES[resp_key]
    n = minutes // bucket
    local = timezone.localtime(now).replace(minute=0, second=0, microsecond=0)
    end = local.replace(hour=0) + timedelta(days=1) if bucket >= 180 else local + timedelta(hours=1)
    start = end - timedelta(minutes=minutes)
    acc = defaultdict(list)
    for at, ms in DomainCheck.objects.filter(domain_id__in=ids, checked_at__gte=start, checked_at__lt=end,
                                             response_ms__isnull=False).values_list("checked_at", "response_ms"):
        acc[int((at - start).total_seconds() // (bucket * 60))].append(ms)
    times = [timezone.localtime(start + timedelta(minutes=bucket * i)) for i in range(n)]
    resp = {"labels": [t.strftime(fmt) for t in times], "tipLabels": [t.strftime("%d %b %H:%M") for t in times],
            "unit": "ms", "xLabelEvery": every, "yTicks": 5,
            "series": [{"name": "Average Response Time", "color": "#1565f0", "area": True, "areaOpacity": 0.14, "width": 1.6,
                        "values": [round(sum(acc[i]) / len(acc[i]), 1) if acc.get(i) else None for i in range(n)]}]}

    # uptime per day
    up_key = request.GET.get("up_range") if request.GET.get("up_range") in UP_RANGES else "7"
    up_label, ndays, up_every = UP_RANGES[up_key]
    today = timezone.localdate()
    per_day = defaultdict(lambda: [0, 0])
    for at, up in DomainCheck.objects.filter(domain_id__in=ids, checked_at__date__gte=today - timedelta(days=ndays - 1)).values_list("checked_at", "up"):
        p = per_day[timezone.localtime(at).date()]
        p[0] += 1
        p[1] += up
    days = [today - timedelta(days=ndays - 1 - i) for i in range(ndays)]
    up_series = [round(100 * per_day[d][1] / per_day[d][0], 2) if per_day[d][0] else None for d in days]
    known = [v for v in up_series if v is not None]
    y_min = min(99.5, max(0.0, math.floor(2 * (min(known) - 0.5)) / 2)) if known else 95.0
    uptime_chart = {"labels": [d.strftime("%b %d") for d in days], "unit": "%", "yMin": y_min, "yMax": 100, "yTicks": 4,
                    "xLabelEvery": up_every,
                    "series": [{"name": "Overall Uptime", "color": "#16a34a", "area": True, "areaOpacity": 0.3, "values": up_series, "width": 1.6}]}

    # trends against the previous period, all from stored records
    week_ago = now - timedelta(days=7)
    total_before = sum(1 for d in domains if d.created_at <= week_ago)
    resp_now = DomainCheck.objects.filter(domain_id__in=ids, checked_at__gte=now - timedelta(hours=24), response_ms__isnull=False)
    resp_prev = DomainCheck.objects.filter(domain_id__in=ids, checked_at__gte=now - timedelta(hours=48),
                                           checked_at__lt=now - timedelta(hours=24), response_ms__isnull=False)
    overall = _uptime(ids, 24 * 7)
    overall_prev = _uptime(ids, 24 * 7, end=week_ago)
    uptime = _mean(overall.values())
    uptime_prev = _mean(overall_prev.values())
    trend = {
        "total": _change(total, total_before),
        "resp": _change(_mean(resp_now.values_list("response_ms", flat=True)), _mean(resp_prev.values_list("response_ms", flat=True))),
        "uptime": round(uptime - uptime_prev, 2) if uptime is not None and uptime_prev is not None else None,
    }

    qs = _filter(scope, request)
    sort = request.GET.get("sort", "")
    if sort in SORTS:
        qs = qs.order_by(*SORTS[sort])
    page = Paginator(qs, _per_page(request)).get_page(request.GET.get("page"))
    up7 = _uptime([d.pk for d in page], 24 * 7)
    for d in page:
        d.uptime7 = up7.get(d.pk)
    resp_vals = [d.response_ms for d in domains if d.response_ms is not None]
    pct = lambda n: 100.0 * n / total if total else 0  # noqa: E731
    # the donut needs one slice per domain: paused first, then down, then SSL expiring, then healthy
    slices = {"healthy": 0, "down": 0, "expiring": 0, "paused": 0, "other": 0}
    for d in domains:
        if not d.monitor_enabled:
            slices["paused"] += 1
        elif d.status == "down":
            slices["down"] += 1
        elif d.ssl_status in ("Expiring", "Expired"):
            slices["expiring"] += 1
        elif d in healthy:
            slices["healthy"] += 1
        else:
            slices["other"] += 1
    legend = [("Healthy", "fill-ok", "#16a34a", slices["healthy"]), ("Down", "fill-crit", "#ef4444", slices["down"]),
              ("SSL Expiring", "fill-warn", "#f59e0b", slices["expiring"]), ("Paused", "", "#94a3b8", slices["paused"])]
    if slices["other"]:
        legend.append(("Other issues", "", "#64748b", slices["other"]))
    legend = [{"label": l, "cls": c, "color": col, "n": v, "pct": pct(v)} for l, c, col, v in legend]
    return _render(request, "domainmonitor/overview.html", {
        "tab": "overview", "page": page, "query": _query(request), "sort_query": _query(request, "sort"), "sort": sort,
        "total": total, "trend": trend,
        "n": {"healthy": len(healthy), "down": len(down), "expiring": len(expiring), "paused": len(paused)},
        "p": {"healthy": pct(len(healthy)), "down": pct(len(down)), "expiring": pct(len(expiring)), "paused": pct(len(paused))},
        "avg_ms": _mean(resp_vals), "uptime": uptime,
        "legend": legend,
        "donut": {"segments": [{"label": x["label"], "value": x["n"], "color": x["color"]} for x in legend],
                  "center": {"value": str(total), "label": "Domains"}, "thickness": 26},
        "resp": resp, "uptime_chart": uptime_chart,
        "resp_range": resp_key, "up_range": up_key, "resp_ranges": [(k, v[0]) for k, v in RESP_RANGES.items()],
        "up_ranges": [(k, v[0]) for k, v in UP_RANGES.items()],
        "groups": scope.exclude(group="").order_by().values_list("group", flat=True).distinct(),
        "ssl_states": SSL_STATES,
    })


# ------------------------------------------------------------------ list (configuration view)
def domain_list(request):
    scope = _scope(request)
    qs = _filter(scope, request)
    paginator = Paginator(qs, _per_page(request))
    sel_pk, edit_pk = _int(request.GET.get("selected")), _int(request.GET.get("edit"))
    selected = scope.filter(pk=sel_pk).first() if sel_pk else None
    page_no = request.GET.get("page")
    if selected and not page_no:
        # open the page that holds the selected domain, so its row is highlighted
        ids = list(qs.values_list("pk", flat=True))
        if selected.pk in ids:
            page_no = ids.index(selected.pk) // paginator.per_page + 1
    page = paginator.get_page(page_no)
    selected = selected or (page.object_list[0] if page.object_list else None)

    editing = None
    if request.GET.get("edit"):
        editing = get_object_or_404(scope, pk=edit_pk or 0)
    if request.method == "POST":
        if not can(request.user, "operate"):
            messages.error(request, "Only operators can add or change domains.")
            return redirect("domains:list")
        editing = scope.filter(pk=request.POST.get("pk")).first() if request.POST.get("pk") else None
        form = DomainForm(request.POST, instance=editing)
        if form.is_valid():
            obj = form.save(commit=False)
            obj.tenant_key = settings.LINKEDEYE_TENANT
            try:
                obj.save()
            except IntegrityError:
                form.add_error("hostname", "This domain already exists.")
            else:
                audit(request, "update" if editing else "create", obj, hostname=obj.hostname, site=obj.site_key,
                      type=obj.domain_type, monitor_enabled=obj.monitor_enabled)
                if obj.monitor_enabled and obj.is_active:
                    runner.run_domain_checks([obj])
                messages.success(request, f"Saved {obj.hostname}.")
                return redirect(f"{request.path}?selected={obj.pk}")
    else:
        form = DomainForm(instance=editing)

    all_active = scope.filter(is_active=True)
    total = scope.count()
    active = all_active.count()
    month_ago = timezone.now() - timedelta(days=30)
    before = scope.filter(created_at__lte=month_ago).count()
    expiring = all_active.filter(ssl_status__in=["Expiring", "Expired"]).count()
    dns_issues = all_active.filter(dns_status="Failed").count()
    share = lambda n: round(100.0 * n / active, 1) if active else None  # noqa: E731

    detail = {}
    if selected:
        history = list(selected.checks.all()[:50])
        ips = {}
        for c in history:
            if c.ip_address:
                row = ips.setdefault(c.ip_address, {"ip": c.ip_address, "type": "AAAA" if ":" in c.ip_address else "A",
                                                    "first": c.checked_at, "last": c.checked_at, "seen": 0})
                row["seen"] += 1
                row["first"] = min(row["first"], c.checked_at)
                row["last"] = max(row["last"], c.checked_at)
        up7 = _uptime([selected.pk], 24 * 7).get(selected.pk)
        detail = {
            "recent": history[:8], "dns_records": sorted(ips.values(), key=lambda r: r["last"], reverse=True),
            "dns_failures": sum(1 for c in history if c.dns_status == "Failed"), "history_n": len(history),
            "ssl_history": [c for c in history if c.ssl_expires_at or c.ssl_status != "Unknown"][:5],
            "uptime7": up7,
            "siblings": scope.filter(site_key=selected.site_key).exclude(pk=selected.pk).order_by("hostname")[:8],
            "services": associated_services(selected),
        }
    dtab = request.GET.get("dtab", "overview")
    return _render(request, "domainmonitor/list.html", {
        "tab": "list", "page": page, "query": _query(request), "selected": selected, "form": form, "editing": editing,
        "show_form": bool(editing) or request.GET.get("add") == "1" or request.method == "POST",
        "dtab": dtab if dtab in ("overview", "dns", "ssl", "site", "history") else "overview", **detail,
        "more_open": bool(request.GET.get("dns") or request.GET.get("ssl")),
        "k": {"total": total, "active": active, "inactive": total - active, "expiring": expiring, "dns": dns_issues,
              "growth": _change(total, before), "active_pct": round(100.0 * active / total, 1) if total else None,
              "expiring_pct": share(expiring), "dns_pct": share(dns_issues),
              "sites": all_active.order_by().values("site_key").distinct().count()},
        "sites": scope.order_by("site_key").values_list("site_key", flat=True).distinct(),
        "types": scope.order_by("domain_type").values_list("domain_type", flat=True).distinct(),
        "ssl_states": SSL_STATES, "dns_states": DNS_STATES,
    })


def dns_records(request):
    """Resolved addresses per domain, taken from the stored DomainCheck rows."""
    domains = list(_filter(_scope(request).filter(is_active=True), request))
    since = timezone.now() - timedelta(days=7)
    seen = defaultdict(dict)
    fails = defaultdict(int)
    checks_n = defaultdict(int)
    for dom_id, ip, at, dns in (DomainCheck.objects.filter(domain_id__in=[d.pk for d in domains], checked_at__gte=since)
                                .values_list("domain_id", "ip_address", "checked_at", "dns_status")):
        checks_n[dom_id] += 1
        if dns == "Failed":
            fails[dom_id] += 1
        if ip:
            row = seen[dom_id].setdefault(ip, {"ip": ip, "type": "AAAA" if ":" in ip else "A", "last": at, "n": 0})
            row["n"] += 1
            row["last"] = max(row["last"], at)
    for d in domains:
        d.records = sorted(seen[d.pk].values(), key=lambda r: r["last"], reverse=True)
        d.fail_n = fails[d.pk]
        d.checks_n = checks_n[d.pk]
    return _render(request, "domainmonitor/dns.html", {
        "tab": "dns", "crumb": "DNS Records", "rows": domains, "query": _query(request),
        "k": {"resolved": sum(1 for d in domains if d.dns_status == "Resolved"),
              "failed": sum(1 for d in domains if d.dns_status == "Failed"),
              "changed": sum(1 for d in domains if len(d.records) > 1),
              "ips": len({r["ip"] for d in domains for r in d.records})},
        "dns_states": DNS_STATES,
    })


def ssl_certificates(request):
    rows = sorted(_scope(request).filter(is_active=True), key=lambda d: (d.ssl_expires_at is None, d.ssl_expires_at or timezone.now()))
    return _render(request, "domainmonitor/ssl.html", {"tab": "ssl", "rows": rows, "crumb": "SSL Certificates"})


def export_csv(request):
    qs = _filter(_scope(request), request)
    if request.GET.get("sort") in SORTS:
        qs = qs.order_by(*SORTS[request.GET["sort"]])
    up7 = _uptime(list(qs.values_list("pk", flat=True)), 24 * 7)
    resp = HttpResponse(content_type="text/csv")
    resp["Content-Disposition"] = 'attachment; filename="domains.csv"'
    w = csv.writer(resp)
    w.writerow(["hostname", "type", "site", "group", "active", "status", "ip_address", "response_ms", "uptime_7d",
                "dns_status", "ssl_status", "ssl_expires_at", "last_checked_at", "description"])
    for d in qs:
        u = up7.get(d.pk)
        w.writerow([d.hostname, d.domain_type, d.site_key, d.group, "yes" if d.is_active else "no", d.status, d.ip_address or "",
                    "" if d.response_ms is None else round(d.response_ms), "" if u is None else f"{u:.2f}",
                    d.dns_status, d.ssl_status, d.ssl_expires_at.isoformat() if d.ssl_expires_at else "",
                    d.last_checked_at.isoformat() if d.last_checked_at else "", d.description])
    return resp


@require_POST
@require("operate")
def deactivate(request, pk):
    d = get_object_or_404(_scope(request), pk=pk)
    d.is_active = not d.is_active
    d.save(update_fields=["is_active", "updated_at"])
    audit(request, "update", d, is_active=d.is_active)
    messages.success(request, f"{d.hostname} {'reactivated' if d.is_active else 'deactivated'}.")
    return redirect(f"/domains/list/?selected={d.pk}")


# ------------------------------------------------------------------ quick actions (JSON)
@require_POST
@require("operate")
def action(request, pk, kind):
    d = get_object_or_404(_scope(request), pk=pk)
    if kind in ("dns", "ssl", "uptime"):
        audit(request, "run", d, check=kind)
    if kind == "dns":
        r = checks.dns_check(d.hostname)
        summary = f"{d.hostname} resolves to {', '.join(r.ips)}" if r.ok else r.error
        return JsonResponse({"ok": r.ok, "ips": r.ips, "summary": summary})
    if kind == "ssl":
        r = checks.tls_check(d.hostname)
        if r.expires_at:
            summary = f"{r.status}: expires {timezone.localtime(r.expires_at):%d %b %Y} ({r.days_left} days)\nIssuer: {r.issuer}\nSubject: {r.subject}"
        else:
            summary = f"{r.status}: {r.error}"
        return JsonResponse({"status": r.status, "days_left": r.days_left, "summary": summary})
    if kind == "uptime":
        runner.run_domain_checks([d])
        d.refresh_from_db()
        summary = (f"{d.status.upper()} · HTTP {d.http_status or '–'} · {d.response_ms or 0:.0f} ms · DNS {d.dns_status} · SSL {d.ssl_status}"
                   + (f"\n{d.last_error}" if d.last_error else ""))
        return JsonResponse({"status": d.status, "summary": summary})
    return JsonResponse({"error": "unknown action"}, status=404)


@require_POST
@require("operate")
def run_all(request):
    items = list(_scope(request).filter(is_active=True, monitor_enabled=True))
    runner.run_domain_checks(items)
    audit(request, "run", None, object_type="domainmonitor.domain", check="all", count=len(items))
    return JsonResponse({"checked": len(items), "summary": f"Checked {len(items)} domain(s)"})


# ------------------------------------------------------------------ JSON API (contract from the integration patch)
# SECURITY: staff-only until existing tenant RBAC and site membership are mapped.

@staff_member_required
def page(request):
    return redirect("domains:list")


@staff_member_required
@require_http_methods(["GET", "POST"])
def api_domains(request):
    if request.method == "GET":
        tenant = request.GET.get("tenant", "").strip()
        if not tenant:
            return JsonResponse({"error": "tenant query parameter required"}, status=400)
        rows = Domain.objects.filter(tenant_key=tenant)
        return JsonResponse({"results": [{
            "id": x.id, "hostname": x.hostname, "site": x.site_key,
            "type": x.domain_type, "active": x.is_active,
            "dns": x.dns_status, "ssl": x.ssl_status,
            "description": x.description,
            "status": x.status, "ip": x.ip_address, "response_ms": x.response_ms,
            "ssl_expires_at": x.ssl_expires_at.isoformat() if x.ssl_expires_at else None,
            "last_checked_at": x.last_checked_at.isoformat() if x.last_checked_at else None,
        } for x in rows[:500]]})
    try:
        data = json.loads(request.body)
        tenant = str(data["tenant"]).strip()
        site = str(data["site"]).strip()
        hostname = str(data["hostname"]).strip().lower().rstrip(".")
        if not tenant or not site:
            return JsonResponse({"error": "tenant and site are required"}, status=400)
        obj = Domain(tenant_key=tenant, site_key=site, hostname=hostname,
                     domain_type=str(data.get("type", "Production"))[:32],
                     description=str(data.get("description", ""))[:5000])
        obj.full_clean()
        obj.save()
        return JsonResponse({"id": obj.pk, "status": "created"}, status=201)
    except (KeyError, ValueError, TypeError, json.JSONDecodeError, ValidationError) as exc:
        return JsonResponse({"error": str(exc)}, status=400)


@staff_member_required
@require_http_methods(["PATCH", "DELETE"])
def api_detail(request, pk):
    tenant = request.GET.get("tenant", "").strip()
    if not tenant:
        return JsonResponse({"error": "tenant required"}, status=400)
    try:
        obj = Domain.objects.get(pk=pk, tenant_key=tenant)
    except Domain.DoesNotExist:
        return JsonResponse({"error": "Not found"}, status=404)
    if request.method == "DELETE":
        obj.is_active = False  # non-destructive deactivation
        obj.save(update_fields=["is_active", "updated_at"])
        return JsonResponse({"status": "deactivated"})
    try:
        data = json.loads(request.body)
        allowed = {"site": "site_key", "type": "domain_type", "description": "description", "active": "is_active"}
        for key, field in allowed.items():
            if key in data:
                setattr(obj, field, data[key])
        obj.full_clean()
        obj.save()
        return JsonResponse({"status": "updated"})
    except (ValueError, TypeError, ValidationError) as exc:
        return JsonResponse({"error": str(exc)}, status=400)
