"""Numbers for the Incidents overview, all computed from real tickets.

The selected period is the last N local days (today included); the previous period is the N days before
it, used for the KPI deltas."""
import math
from collections import Counter
from datetime import datetime, time, timedelta

from django.db.models import Count, Q
from django.utils import timezone

from . import sla
from . import workflow as wf

RANGES = [(7, "Last 7 days"), (15, "Last 15 days"), (30, "Last 30 days"), (90, "Last 90 days")]
DEFAULT_RANGE = 15
CATEGORY_COLORS = ["#1565f0", "#6366f1", "#818cf8", "#10b981", "#f59e0b", "#ef4444", "#94a3b8", "#0ea5e9"]
AVATAR_COLORS = ["#1565f0", "#7c3aed", "#0f766e", "#b45309", "#db2777", "#4f46e5", "#0369a1", "#15803d", "#be123c"]
SLA_COLORS = {"met": "#16a34a", "on_track": "#1d7cf2", "at_risk": "#f5b400", "breached": "#ef4444"}
PRIORITY_KPI = {  # glyph, tile tone
    "P1": ("flame", "crit"), "P2": ("info", "orange"), "P3": ("info", "amber"), "P4": ("info", "blue"),
}


def parse_range(value):
    try:
        days = int(value)
    except (TypeError, ValueError):
        return DEFAULT_RANGE
    return days if days in dict(RANGES) else DEFAULT_RANGE


def period(days, now=None):
    """(start, end, prev_start) as aware datetimes: start = local midnight `days-1` days ago."""
    now = now or timezone.now()
    today = timezone.localdate(now)
    start = timezone.make_aware(datetime.combine(today - timedelta(days=days - 1), time.min))
    return start, now, start - timedelta(days=days)


def pct_change(now, before):
    if not before:
        return None
    return round(100.0 * (now - before) / before)


def avatar_color(user):
    key = user.get_username() if user is not None else ""
    return AVATAR_COLORS[sum(map(ord, key)) % len(AVATAR_COLORS)] if key else "#d5dbe4"


def initials(user):
    name = (user.get_full_name() or user.get_username()).replace(".", " ").replace("_", " ")
    parts = [p for p in name.split() if p]
    return "".join(p[0] for p in parts[:2]).upper() or "?"


def nice_max(v, ticks=4):
    """Smallest 'nice' axis maximum >= v whose `ticks` gridlines fall on whole numbers."""
    need = max(1, math.ceil(v / ticks))
    for c in (1, 2, 3, 4, 5, 6, 8, 10, 12, 15, 20, 25, 30, 40, 50, 60, 75, 100):
        if c >= need:
            return ticks * c
    p = 10 ** math.floor(math.log10(need))
    return ticks * math.ceil(need / p) * p


def overview(qs, days, now=None):
    """qs: incidents already scoped (tenant, site, client). Returns the context for the overview page."""
    now = now or timezone.now()
    start, end, prev_start = period(days, now)
    cur = qs.filter(opened_at__gte=start, opened_at__lte=end)
    prev = qs.filter(opened_at__gte=prev_start, opened_at__lt=start)

    # ---- KPIs
    cur_by_p = dict(cur.values_list("priority").annotate(n=Count("pk")).order_by())
    prev_by_p = dict(prev.values_list("priority").annotate(n=Count("pk")).order_by())
    unassigned = dict(cur.open().filter(assignee__isnull=True).values_list("priority").annotate(n=Count("pk")).order_by())
    total, total_prev = sum(cur_by_p.values()), sum(prev_by_p.values())
    open_n = cur.open().count()
    kpis = [{"key": "", "label": "Total Incidents", "value": total, "delta": pct_change(total, total_prev),
             "sub": f"{open_n} open, {total - open_n} resolved", "glyph": "alert", "tone": "crit", "prev": total_prev}]
    for p, label in wf.PRIORITIES:
        glyph, tone = PRIORITY_KPI[p]
        n = unassigned.get(p, 0)
        kpis.append({"key": p, "label": label, "value": cur_by_p.get(p, 0), "prev": prev_by_p.get(p, 0),
                     "delta": pct_change(cur_by_p.get(p, 0), prev_by_p.get(p, 0)),
                     "sub": f"{n} unassigned", "glyph": glyph, "tone": tone})

    # ---- created vs resolved per local day
    day_list = [timezone.localdate(start) + timedelta(days=i) for i in range(days)]
    created = Counter(timezone.localdate(t) for t in cur.values_list("opened_at", flat=True))
    resolved = Counter(timezone.localdate(t) for t in
                       qs.filter(resolved_at__gte=start, resolved_at__lte=end).values_list("resolved_at", flat=True))
    c_vals, r_vals = [created.get(d, 0) for d in day_list], [resolved.get(d, 0) for d in day_list]
    every = max(1, math.ceil(days / 8))
    trend = {"labels": [d.strftime("%b %-d") for d in day_list], "tipLabels": [d.strftime("%a, %b %-d") for d in day_list],
             "unit": "", "yMin": 0, "yMax": nice_max(max(c_vals + r_vals + [0])), "yTicks": 4, "xLabelEvery": every,
             "series": [{"name": "Created", "color": "#1d7cf2", "values": c_vals, "area": True, "areaOpacity": 0.2, "width": 2},
                        {"name": "Resolved", "color": "#16a34a", "values": r_vals, "area": True, "areaOpacity": 0.2, "width": 2}]}

    # ---- status donut
    by_status = dict(cur.values_list("status").annotate(n=Count("pk")).order_by())
    segments = [{"key": s, "label": wf.STATUS_LABELS[s], "value": by_status.get(s, 0), "color": wf.STATUS_COLOR[s]}
                for s in wf.FLOW["incident"]]
    status = {"segments": segments, "center": {"value": str(total), "label": "Total"}, "thickness": 24}

    # ---- SLA compliance (incidents of the period that carry an SLA)
    counts = Counter()
    for t in cur.filter(Q(resolution_due__isnull=False) | Q(response_due__isnull=False)).only(
            "status", "response_due", "resolution_due", "acknowledged_at", "resolved_at", "opened_at",
            "response_breached", "resolution_breached", "kind"):
        state = sla.overall(t, now)
        if state != "none":
            counts[state] += 1
    sla_total = sum(counts.values())
    compliant = sla_total - counts["breached"]
    pct = round(100 * compliant / sla_total) if sla_total else None
    sla_legend = [{"key": k, "label": label, "value": counts[k], "color": SLA_COLORS[k]}
                  for k, label in (("met", "Met"), ("on_track", "On Track"), ("at_risk", "At Risk"), ("breached", "Breached"))]
    sla_chart = {"segments": [{"label": "Within SLA", "value": compliant, "color": "#16a34a"},
                              {"label": "Breached", "value": counts["breached"], "color": "#e5e9f0"}],
                 "center": {"value": f"{pct}%" if pct is not None else "–"}, "thickness": 18}

    # ---- categories
    cats = list(cur.values_list("category").annotate(n=Count("pk")).order_by("-n", "category")[:7])
    categories = [{"name": c or "Uncategorised", "value": n, "color": CATEGORY_COLORS[i % len(CATEGORY_COLORS)],
                   "param": c} for i, (c, n) in enumerate(cats)]

    return {
        "start": start, "end": end, "prev_start": prev_start, "days": days,
        "range_label": f"{timezone.localdate(start):%b %-d, %Y} – {timezone.localdate(end):%b %-d, %Y}",
        "kpis": kpis, "trend": trend, "status": status, "status_segments": segments, "total": total,
        "sla": sla_chart, "sla_legend": sla_legend, "sla_pct": pct, "sla_total": sla_total,
        "categories": categories, "cat_max": max([c["value"] for c in categories] + [1]),
    }
