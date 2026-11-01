"""Unified uptime across every monitored target: URL checks, TCP checks and domains.

Uptime is computed from stored results only:
  * URL check  – UrlResult rows; Degraded counts as available, Down does not;
  * TCP check  – TcpResult rows; same rule;
  * domain     – DomainCheck rows; `up` (HTTPS answered below 500).
A target with no results in a window has no uptime for it (shown as "–"), never 100%.
"""
from dataclasses import dataclass, field
from datetime import datetime, time, timedelta
from decimal import Decimal

from django.apps import apps
from django.conf import settings
from django.db.models import Count, Q
from django.db.models.functions import TruncDate
from django.urls import reverse
from django.utils import timezone

from core.access import scope_by_site

from .models import DEFAULT_SLA, SlaTarget, Status
from .services import checks_for

KINDS = [("url", "URL"), ("tcp", "TCP"), ("domain", "Domain")]
KIND_LABEL = dict(KINDS)
KIND_COLOR = {"url": "#1565f0", "tcp": "#7c3aed", "domain": "#0f9488"}
STATUS_ORDER = {"down": 0, "degraded": 1, "unknown": 2, "online": 3}
WINDOWS = {"24h": 24, "7d": 24 * 7, "30d": 24 * 30}


@dataclass
class Target:
    kind: str
    pk: int
    name: str
    address: str
    site: str
    status: str
    last_checked_at: datetime = None
    response_ms: float = None
    detail_url: str = ""
    uptime: dict = field(default_factory=dict)       # {"24h": 99.9 | None, ...}
    samples: dict = field(default_factory=dict)      # {"24h": (up, total), ...}
    sla: Decimal = DEFAULT_SLA
    sla_custom: bool = False

    @property
    def key(self):
        return f"{self.kind}:{self.pk}"

    @property
    def kind_label(self):
        return KIND_LABEL[self.kind]

    @property
    def up24(self):
        return self.uptime.get("24h")

    @property
    def up7(self):
        return self.uptime.get("7d")

    @property
    def up30(self):
        return self.uptime.get("30d")

    @property
    def sla_display(self):
        return sla_text(self.sla)

    @property
    def sla_state(self):
        """met | breached | nodata — judged on 30-day uptime."""
        if self.up30 is None:
            return "nodata"
        return "met" if Decimal(str(round(self.up30, 3))) >= self.sla else "breached"


def sla_text(value):
    """99.900 -> "99.9", 100.000 -> "100"."""
    return f"{Decimal(value).normalize():f}"


def _model(label):
    try:
        return apps.get_model(label)
    except LookupError:
        return None


# ------------------------------------------------------------------ sources
def sources(user):
    """{kind: (target queryset, result queryset factory info)} for each module that is installed."""
    tenant = settings.LINKEDEYE_TENANT
    out = {}
    UrlCheck = _model("urlchecker.UrlCheck")
    if UrlCheck is not None:
        out["url"] = scope_by_site(UrlCheck.objects.filter(tenant_key=tenant, enabled=True), user)
    out["tcp"] = checks_for(user).filter(enabled=True)
    Domain = _model("domainmonitor.Domain")
    if Domain is not None:
        out["domain"] = scope_by_site(Domain.objects.filter(tenant_key=tenant, is_active=True, monitor_enabled=True),
                                      user, field="site_key")
    return out


def _results(kind, targets):
    """(result queryset limited to `targets`, fk name, Q for 'available')."""
    if kind == "url":
        return _model("urlchecker.UrlResult").objects.filter(url_check__in=targets), "url_check_id", ~Q(status="down")
    if kind == "tcp":
        return _model("tcpcheck.TcpResult").objects.filter(tcp_check__in=targets), "tcp_check_id", ~Q(status=Status.DOWN)
    return _model("domainmonitor.DomainCheck").objects.filter(domain__in=targets), "domain_id", Q(up=True)


def _filter(kind, qs, site="", q=""):
    site_field = "site_key" if kind == "domain" else "site"
    if site:
        qs = qs.filter(**{site_field: site})
    if q:
        if kind == "url":
            qs = qs.filter(Q(name__icontains=q) | Q(url__icontains=q) | Q(tags__icontains=q))
        elif kind == "tcp":
            qs = qs.filter(Q(name__icontains=q) | Q(host__icontains=q) | Q(tags__icontains=q))
        else:
            qs = qs.filter(Q(hostname__icontains=q) | Q(description__icontains=q) | Q(group__icontains=q))
    return qs


def _to_target(kind, o):
    if kind == "url":
        return Target("url", o.pk, o.name, o.url, o.site, o.last_status, o.last_checked_at, o.last_response_ms,
                      reverse("urlchecker:detail", args=[o.pk]))
    if kind == "tcp":
        return Target("tcp", o.pk, o.name, o.target, o.site, o.last_status, o.last_checked_at, o.last_response_ms,
                      reverse("tcpcheck:detail", args=[o.pk]))
    status = {"up": "online", "down": "down"}.get(o.status, "unknown")
    try:
        url = reverse("domains:list") + f"?selected={o.pk}"
    except Exception:
        url = ""
    return Target("domain", o.pk, o.hostname, f"https://{o.hostname}/", o.site_key, status, o.last_checked_at,
                  o.response_ms, url)


def _window_stats(kind, targets_qs):
    """{pk: {"24h": (up, total), "7d": ..., "30d": ...}} in one query."""
    now = timezone.now()
    res, fk, up_q = _results(kind, targets_qs)
    agg = {}
    for w, hours in WINDOWS.items():
        since = Q(checked_at__gte=now - timedelta(hours=hours))
        agg[f"t_{w}"] = Count("id", filter=since)
        agg[f"u_{w}"] = Count("id", filter=since & up_q)
    rows = res.filter(checked_at__gte=now - timedelta(hours=max(WINDOWS.values()))).values(fk).annotate(**agg)
    return {r[fk]: {w: (r[f"u_{w}"], r[f"t_{w}"]) for w in WINDOWS} for r in rows}


def collect(user, kind="", site="", q=""):
    """Every monitored target the user may see (optionally filtered), with uptime and SLA filled in."""
    out = []
    srcs = sources(user)
    slas = {(s.kind, s.object_id): s.target
            for s in SlaTarget.objects.filter(tenant_key=settings.LINKEDEYE_TENANT)}
    for k, qs in srcs.items():
        if kind and k != kind:
            continue
        qs = _filter(k, qs, site, q)
        objs = list(qs)
        if not objs:
            continue
        stats = _window_stats(k, qs)
        for o in objs:
            t = _to_target(k, o)
            s = stats.get(o.pk, {})
            for w in WINDOWS:
                up, total = s.get(w, (0, 0))
                t.samples[w] = (up, total)
                t.uptime[w] = 100.0 * up / total if total else None
            if (k, o.pk) in slas:
                t.sla, t.sla_custom = slas[(k, o.pk)], True
            out.append(t)
    return out


def filtered_sources(user, kind="", site="", q=""):
    return {k: _filter(k, qs, site, q) for k, qs in sources(user).items() if not kind or k == kind}


def all_sites(user):
    names = set()
    for k, qs in sources(user).items():
        names |= set(qs.order_by().values_list("site_key" if k == "domain" else "site", flat=True).distinct())
    names |= set(_model("core.Site").objects.filter(tenant_key=settings.LINKEDEYE_TENANT).values_list("name", flat=True))
    return sorted(n for n in names if n)


SORTS = {
    "status": lambda t: (STATUS_ORDER.get(t.status, 9), t.name.lower()),
    "name": lambda t: (t.name.lower(), t.kind),
    "type": lambda t: (t.kind, t.name.lower()),
    "site": lambda t: (t.site.lower(), t.name.lower()),
    "uptime": lambda t: (t.up30 is None, t.up30 if t.up30 is not None else 0, t.name.lower()),
    "sla": lambda t: ({"breached": 0, "nodata": 2, "met": 1}[t.sla_state], t.up30 or 0, t.name.lower()),
}


def sort_targets(targets, key):
    return sorted(targets, key=SORTS.get(key, SORTS["status"]))


def overall(targets, window="30d"):
    up = sum(t.samples.get(window, (0, 0))[0] for t in targets)
    total = sum(t.samples.get(window, (0, 0))[1] for t in targets)
    return 100.0 * up / total if total else None


def daily_availability(srcs, days=30):
    """Line chart data: availability % per day for each target type and overall.
    `srcs` is {kind: target queryset}. Days without any result are gaps."""
    tz = timezone.get_current_timezone()
    today = timezone.localdate()
    start = today - timedelta(days=days - 1)
    since = timezone.make_aware(datetime.combine(start, time.min))
    per = {}
    totals = {}
    for k, qs in srcs.items():
        res, _fk, up_q = _results(k, qs)
        rows = (res.filter(checked_at__gte=since).annotate(day=TruncDate("checked_at", tzinfo=tz)).values("day")
                .annotate(t=Count("id"), u=Count("id", filter=up_q)))
        per[k] = {r["day"]: (r["u"], r["t"]) for r in rows}
        for d, (u, t) in per[k].items():
            a = totals.setdefault(d, [0, 0])
            a[0] += u
            a[1] += t
    labels, tips, all_vals = [], [], []
    series = []
    dates = [start + timedelta(days=i) for i in range(days)]
    for d in dates:
        labels.append(d.strftime("%d %b"))
        tips.append(d.strftime("%a %d %b %Y"))
    for k, label in KINDS:
        if k not in per:
            continue
        vals = [round(100.0 * per[k][d][0] / per[k][d][1], 3) if d in per[k] and per[k][d][1] else None for d in dates]
        if any(v is not None for v in vals):
            series.append({"name": label, "color": KIND_COLOR[k], "values": vals, "width": 1.6})
            all_vals += [v for v in vals if v is not None]
    overall_vals = [round(100.0 * totals[d][0] / totals[d][1], 3) if d in totals and totals[d][1] else None for d in dates]
    if len(series) > 1 and any(v is not None for v in overall_vals):
        series.append({"name": "Overall", "color": "#0f1f3d", "values": overall_vals, "width": 2.4, "endDot": True})
        all_vals += [v for v in overall_vals if v is not None]
    data = {"labels": labels, "tipLabels": tips, "unit": "%", "series": series,
            "xLabelEvery": 5 if days > 14 else 1 if days <= 7 else 2}
    lo = min(all_vals) if all_vals else 100
    # zoom the y axis to the interesting band, in round steps
    for floor in (99.5, 99, 98, 95, 90, 80, 50, 0):
        if lo >= floor:
            break
    data.update({"yMin": floor, "yMax": 100, "yTicks": {98: 4, 80: 4}.get(floor, 5)})
    return data, bool(all_vals)
