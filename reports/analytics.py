"""Cross-module analytics for the Analytics page. All numbers come from stored records.

Each section is computed independently: a missing or unmigrated module turns only its own section into a
"not connected" panel. Daily series use the server's local days; a day without data is None (a gap), not 0.
"""
from datetime import datetime, time, timedelta

from django.apps import apps
from django.conf import settings
from django.db import DatabaseError
from django.core.exceptions import FieldError
from django.db.models import Count, Q
from django.db.models.functions import TruncDate
from django.utils import timezone

from core.access import scope_by_site

RANGES = [(7, "Last 7 days"), (30, "Last 30 days"), (90, "Last 90 days")]
DEFAULT_RANGE = 30
MIN_BASE = 5
PRIORITY_COLORS = {"P1": "#d92d20", "P2": "#ff5b2e", "P3": "#e08a00", "P4": "#2b4cff"}
SEVERITY_COLORS = {"critical": "#d92d20", "warning": "#e08a00", "info": "#2b4cff", "ok": "#0f7a55"}


def parse_range(value):
    try:
        days = int(value)
    except (TypeError, ValueError):
        return DEFAULT_RANGE
    return days if days in dict(RANGES) else DEFAULT_RANGE


class Window:
    def __init__(self, days, now=None):
        self.days = days
        self.now = now or timezone.now()
        today = timezone.localdate(self.now)
        self.dates = [today - timedelta(days=days - 1 - i) for i in range(days)]
        self.start = timezone.make_aware(datetime.combine(self.dates[0], time.min))
        self.prev_start = self.start - timedelta(days=days)
        every = 1 if days <= 7 else (5 if days <= 30 else 14)
        self.labels = [d.strftime("%d %b") for d in self.dates]
        self.x_every = every


def _model(app_label, name):
    if not apps.is_installed(app_label):
        return None
    try:
        return apps.get_model(app_label, name)
    except LookupError:
        return None


def _section(fn):
    def wrapped(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except (DatabaseError, FieldError) as e:
            return {"error": f"Data not available ({type(e).__name__}); run migrations."}
    wrapped.__name__ = fn.__name__
    return wrapped


def _change(now, before):
    if now is None or before in (None, 0):
        return None
    return round(100.0 * (now - before) / before)


def _avg_minutes(pairs):
    vals = [(b - a).total_seconds() / 60 for a, b in pairs if a and b and b >= a]
    return round(sum(vals) / len(vals), 1) if vals else None


def _daily(qs, field, w, **annotations):
    """{date: {name: value}} grouped by local day of `field`."""
    rows = qs.annotate(day=TruncDate(field, tzinfo=timezone.get_current_timezone())).values("day").annotate(**annotations)
    return {r["day"]: r for r in rows}


def _axis_floor(low):
    """Lower bound for a 0-100 % axis: a round number a little below the lowest value."""
    for floor in (99, 95, 90, 80, 50, 0):
        if low >= floor + (0.2 if floor >= 95 else 1):
            return floor
    return 0


@_section
def service_desk(user, w, site=""):
    Ticket = _model("servicedesk", "Ticket")
    if Ticket is None:
        return {"error": "Service Desk is not installed."}
    base = scope_by_site(Ticket.objects.filter(tenant_key=settings.LINKEDEYE_TENANT, kind="incident"), user)
    if site:
        base = base.filter(site=site)
    cur = base.filter(opened_at__gte=w.start, opened_at__lte=w.now)
    prev = base.filter(opened_at__gte=w.prev_start, opened_at__lt=w.start)

    def kpis(qs):
        agg = qs.aggregate(total=Count("id"), breached=Count("id", filter=Q(resolution_breached=True)))
        return {
            "opened": agg["total"],
            "mtta": _avg_minutes(qs.filter(acknowledged_at__isnull=False).values_list("opened_at", "acknowledged_at")),
            "mttr": _avg_minutes(qs.filter(resolved_at__isnull=False).values_list("opened_at", "resolved_at")),
            "sla": round(100.0 * (agg["total"] - agg["breached"]) / agg["total"], 1) if agg["total"] else None,
        }

    k, kp = kpis(cur), kpis(prev)
    # a change against a handful of previous incidents is noise (1 → 69 is not "+6800%"): need MIN_BASE of them
    comparable = kp["opened"] >= MIN_BASE
    resolved_in_window = base.filter(resolved_at__gte=w.start, resolved_at__lte=w.now)
    opened_by_day = _daily(cur, "opened_at", w, n=Count("id"))
    resolved_by_day = _daily(resolved_in_window, "resolved_at", w, n=Count("id"))
    trend = {"labels": w.labels, "xLabelEvery": w.x_every, "stacked": False, "series": [
        {"name": "Opened", "color": "#ff5b2e", "values": [opened_by_day.get(d, {}).get("n", 0) for d in w.dates]},
        {"name": "Resolved", "color": "#0f7a55", "values": [resolved_by_day.get(d, {}).get("n", 0) for d in w.dates]},
    ]}
    by_priority = dict(cur.values_list("priority").annotate(n=Count("id")))
    donut = {"segments": [{"label": p, "value": by_priority.get(p, 0), "color": c} for p, c in PRIORITY_COLORS.items()],
             "center": {"value": k["opened"], "label": "Incidents"}}
    mttr_by_priority = []
    for p in PRIORITY_COLORS:
        sub = cur.filter(priority=p)
        mttr_by_priority.append({"priority": p, "count": by_priority.get(p, 0),
                                 "mtta": _avg_minutes(sub.filter(acknowledged_at__isnull=False).values_list("opened_at", "acknowledged_at")),
                                 "mttr": _avg_minutes(sub.filter(resolved_at__isnull=False).values_list("opened_at", "resolved_at"))})
    top_cis = list(cur.exclude(ci_name="").values("ci_name").annotate(n=Count("id")).order_by("-n", "ci_name")[:8])
    return {
        "kpi": k, "change": {key: (_change(k[key], kp[key]) if comparable else None) for key in k},
        "prev_opened": kp["opened"],
        "resolved": resolved_in_window.count(), "open_now": base.open().count(),
        "trend": trend, "donut": donut, "mttr_by_priority": mttr_by_priority, "top_cis": top_cis,
        "has_data": bool(k["opened"] or resolved_in_window.exists()),
    }


@_section
def availability(user, w, site=""):
    UrlCheck, UrlResult = _model("urlchecker", "UrlCheck"), _model("urlchecker", "UrlResult")
    Domain, DomainCheck = _model("domainmonitor", "Domain"), _model("domainmonitor", "DomainCheck")
    out = {"series": [], "least": []}
    if UrlCheck is not None:
        checks = scope_by_site(UrlCheck.objects.filter(tenant_key=settings.LINKEDEYE_TENANT), user)
        if site:
            checks = checks.filter(site=site)
        res = UrlResult.objects.filter(url_check__in=checks)

        def url_pct(qs):
            a = qs.aggregate(t=Count("id"), up=Count("id", filter=~Q(status="down")))
            return round(100.0 * a["up"] / a["t"], 2) if a["t"] else None

        cur = res.filter(checked_at__gte=w.start, checked_at__lte=w.now)
        out["url"] = url_pct(cur)
        out["url_prev"] = url_pct(res.filter(checked_at__gte=w.prev_start, checked_at__lt=w.start))
        out["url_checks"] = checks.count()
        daily = _daily(cur, "checked_at", w, t=Count("id"), up=Count("id", filter=~Q(status="down")))
        out["series"].append({"name": "URL checks", "color": "#ff5b2e", "endDot": True, "values": [
            round(100.0 * daily[d]["up"] / daily[d]["t"], 2) if d in daily and daily[d]["t"] else None for d in w.dates]})
        least = (cur.values("url_check_id", "url_check__name", "url_check__site")
                 .annotate(t=Count("id"), up=Count("id", filter=~Q(status="down"))).filter(t__gt=0))
        out["least"] = sorted(({"name": r["url_check__name"], "site": r["url_check__site"], "kind": "URL",
                                "pk": r["url_check_id"], "pct": round(100.0 * r["up"] / r["t"], 2), "samples": r["t"]}
                               for r in least), key=lambda r: (r["pct"], r["name"]))[:8]
    if Domain is not None:
        doms = scope_by_site(Domain.objects.filter(tenant_key=settings.LINKEDEYE_TENANT), user, field="site_key")
        if site:
            doms = doms.filter(site_key=site)
        res = DomainCheck.objects.filter(domain__in=doms)

        def dom_pct(qs):
            a = qs.aggregate(t=Count("id"), up=Count("id", filter=Q(up=True)))
            return round(100.0 * a["up"] / a["t"], 2) if a["t"] else None

        cur = res.filter(checked_at__gte=w.start, checked_at__lte=w.now)
        out["domain"] = dom_pct(cur)
        out["domain_prev"] = dom_pct(res.filter(checked_at__gte=w.prev_start, checked_at__lt=w.start))
        out["domains"] = doms.count()
        daily = _daily(cur, "checked_at", w, t=Count("id"), up=Count("id", filter=Q(up=True)))
        out["series"].append({"name": "Domains", "color": "#2b4cff", "dash": "5 4", "endDot": True, "values": [
            round(100.0 * daily[d]["up"] / daily[d]["t"], 2) if d in daily and daily[d]["t"] else None for d in w.dates]})
        least = (cur.values("domain_id", "domain__hostname", "domain__site_key")
                 .annotate(t=Count("id"), up=Count("id", filter=Q(up=True))).filter(t__gt=0))
        out["least"] += [{"name": r["domain__hostname"], "site": r["domain__site_key"], "kind": "Domain",
                          "pk": r["domain_id"], "pct": round(100.0 * r["up"] / r["t"], 2), "samples": r["t"]}
                         for r in least]
        out["least"] = sorted(out["least"], key=lambda r: (r["pct"], r["name"]))[:8]
    if UrlCheck is None and Domain is None:
        return {"error": "Neither the URL Checker nor Domains is installed."}
    lows = [v for s in out["series"] for v in s["values"] if v is not None]
    y_min = _axis_floor(min(lows)) if lows else 0
    span = 100 - y_min
    step = next(s for s in (1, 2, 5, 10, 20, 25) if span / s <= 5)
    out["chart"] = {"labels": w.labels, "xLabelEvery": w.x_every, "unit": "%", "series": out["series"],
                    "yMin": y_min, "yMax": 100, "yTicks": int(span // step)}
    out["url_change"] = round(out["url"] - out["url_prev"], 2) if out.get("url") is not None and out.get("url_prev") is not None else None
    out["domain_change"] = round(out["domain"] - out["domain_prev"], 2) if out.get("domain") is not None and out.get("domain_prev") is not None else None
    out["has_data"] = bool(lows)
    return out


@_section
def events(user, w, site=""):
    Event = _model("core", "Event")
    qs = scope_by_site(Event.objects.filter(tenant_key=settings.LINKEDEYE_TENANT,
                                            occurred_at__gte=w.start, occurred_at__lte=w.now), user)
    if site:
        qs = qs.filter(site=site)
    by_sev = dict(qs.values_list("severity").annotate(n=Count("id")))
    by_source = list(qs.values("source").annotate(n=Count("id")).order_by("-n", "source")[:8])
    daily = _daily(qs, "occurred_at", w,
                   crit=Count("id", filter=Q(severity="critical")), warn=Count("id", filter=Q(severity="warning")))
    chart = {"labels": w.labels, "xLabelEvery": w.x_every, "series": [
        {"name": "Critical", "color": SEVERITY_COLORS["critical"], "values": [daily.get(d, {}).get("crit", 0) for d in w.dates]},
        {"name": "Warning", "color": SEVERITY_COLORS["warning"], "values": [daily.get(d, {}).get("warn", 0) for d in w.dates]},
    ]}
    total = sum(by_sev.values())
    top_fp = list(qs.exclude(fingerprint="").values("fingerprint", "source").annotate(n=Count("id")).order_by("-n", "fingerprint")[:8])
    return {"total": total, "by_severity": [{"severity": s, "n": by_sev.get(s, 0), "color": c} for s, c in SEVERITY_COLORS.items()],
            "by_source": by_source, "chart": chart, "top_fingerprints": top_fp, "has_data": bool(total)}


@_section
def inventory(user, site=""):
    out = {}
    CI = _model("cmdb", "ConfigurationItem")
    if CI is not None:
        qs = scope_by_site(CI.objects.filter(tenant_key=settings.LINKEDEYE_TENANT), user)
        if site:
            qs = qs.filter(site=site)
        out["cis"] = qs.count()
        out["ci_status"] = list(qs.values("status").annotate(n=Count("id")).order_by("-n"))
    Device = _model("network", "Device")
    if Device is not None:
        qs = scope_by_site(Device.objects.filter(tenant_key=settings.LINKEDEYE_TENANT), user)
        if site:
            qs = qs.filter(site=site)
        out["devices"] = qs.count()
        out["device_status"] = dict(qs.values_list("status").annotate(n=Count("id")))
    TcpCheck = _model("tcpcheck", "TcpCheck")
    if TcpCheck is not None and hasattr(TcpCheck, "last_status"):
        qs = scope_by_site(TcpCheck.objects.all(), user)
        if site:
            qs = qs.filter(site=site)
        out["tcp"] = qs.count()
        out["tcp_status"] = dict(qs.values_list("last_status").annotate(n=Count("id")))
    return out
