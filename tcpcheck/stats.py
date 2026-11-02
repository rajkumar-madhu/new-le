"""Aggregations for the Telnet Monitoring page and check detail (computed from stored TcpResult rows)."""
from collections import defaultdict
from datetime import datetime, time, timedelta

from django.db.models import Avg, Count, Q
from django.utils import timezone

from urlchecker.stats import axis_scale

from .models import Status, TcpResult

# Theme palette (see core/static/linkedeye/app.css): ok green, crit red, warn amber, stone for "not checked".
COLORS = {"online": "#0f7a55", "down": "#d92d20", "degraded": "#e08a00", "unknown": "#a8a398"}


def _results(checks):
    return TcpResult.objects.filter(tcp_check__in=checks)


def status_counts(checks):
    counts = {s: 0 for s in Status.values}
    for c in checks:
        counts[c.last_status] = counts.get(c.last_status, 0) + 1
    return counts


def uptime_map(checks, hours):
    """{check_id: uptime %} over the window; Degraded counts as available."""
    since = timezone.now() - timedelta(hours=hours)
    rows = (_results(checks).filter(checked_at__gte=since).values("tcp_check_id")
            .annotate(total=Count("id"), up=Count("id", filter=~Q(status=Status.DOWN))))
    return {r["tcp_check_id"]: 100.0 * r["up"] / r["total"] for r in rows if r["total"]}


def overall_uptime(checks, hours):
    since = timezone.now() - timedelta(hours=hours)
    agg = _results(checks).filter(checked_at__gte=since).aggregate(
        total=Count("id"), up=Count("id", filter=~Q(status=Status.DOWN)))
    return 100.0 * agg["up"] / agg["total"] if agg["total"] else None


def avg_response(checks, hours=24, offset_hours=0):
    """Mean connect time over [now - offset - hours, now - offset)."""
    end = timezone.now() - timedelta(hours=offset_hours)
    qs = _results(checks).filter(checked_at__gte=end - timedelta(hours=hours), response_ms__isnull=False)
    if offset_hours:
        qs = qs.filter(checked_at__lt=end)
    return qs.aggregate(v=Avg("response_ms"))["v"]


def response_trend(checks, hours=24, buckets=48):
    """Average / minimum / maximum connect time per time bucket. Empty buckets are None (gaps, not zero)."""
    now = timezone.now()
    size = hours * 3600 / buckets
    start = now - timedelta(hours=hours)
    acc = defaultdict(list)
    rows = _results(checks).filter(checked_at__gte=start, response_ms__isnull=False).values_list("checked_at", "response_ms")
    for at, v in rows:
        acc[min(buckets - 1, int((at - start).total_seconds() // size))].append(v)
    labels, tips, avg, mn, mx = [], [], [], [], []
    for i in range(buckets):
        t = timezone.localtime(start + timedelta(seconds=size * i))
        labels.append(t.strftime("%H:%M"))
        tips.append(t.strftime("%d %b %H:%M"))
        v = acc.get(i)
        avg.append(round(sum(v) / len(v), 1) if v else None)
        mn.append(min(v) if v else None)
        mx.append(max(v) if v else None)
    data = {"labels": labels, "tipLabels": tips, "unit": "ms", "series": [
        {"name": "Average", "color": "#2b4cff", "values": avg, "width": 2},
        {"name": "Minimum", "color": COLORS["online"], "values": mn},
        {"name": "Maximum", "color": COLORS["down"], "values": mx, "area": True, "areaOpacity": 0.08},
    ]}
    data.update(axis_scale(max((v for v in mx if v is not None), default=0)))
    return data


def daily_history(checks, days=7):
    """Per day, how many checks were Online / Degraded / Down.
    A check counts as Down for a day if >5% of its results were down, Degraded if >5% were degraded."""
    today = timezone.localdate()
    start = today - timedelta(days=days - 1)
    since = timezone.make_aware(datetime.combine(start, time.min))
    per = defaultdict(lambda: defaultdict(lambda: [0, 0, 0]))  # day -> check -> [total, down, degraded]
    for cid, at, st in _results(checks).filter(checked_at__gte=since).values_list("tcp_check_id", "checked_at", "status"):
        c = per[timezone.localtime(at).date()][cid]
        c[0] += 1
        c[1] += st == Status.DOWN
        c[2] += st == Status.DEGRADED
    labels, online, degraded, down = [], [], [], []
    for i in range(days):
        d = start + timedelta(days=i)
        labels.append(d.strftime("%b %d"))
        o = g = x = 0
        for total, dn, dg in per[d].values():
            if dn / total > 0.05:
                x += 1
            elif dg / total > 0.05:
                g += 1
            else:
                o += 1
        online.append(o or None)
        degraded.append(g or None)
        down.append(x or None)
    data = {"labels": labels, "xLabelEvery": 1, "series": [
        {"name": "Online", "color": COLORS["online"], "values": online},
        {"name": "Down", "color": COLORS["down"], "values": down},
        {"name": "Degraded", "color": COLORS["degraded"], "values": degraded},
    ]}
    peak = max((sum(s["values"][i] or 0 for s in data["series"]) for i in range(days)), default=0)
    data.update(axis_scale(peak))
    return data


def donut(counts, total, label="Total Checks"):
    return {"segments": [
        {"label": "Online", "value": counts.get("online", 0), "color": COLORS["online"]},
        {"label": "Down", "value": counts.get("down", 0), "color": COLORS["down"]},
        {"label": "Degraded", "value": counts.get("degraded", 0), "color": COLORS["degraded"]},
        {"label": "Not checked", "value": counts.get("unknown", 0), "color": COLORS["unknown"]}],
        "center": {"value": str(total), "label": label}}
