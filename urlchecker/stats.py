"""Aggregations for the URL Checker dashboard (computed from stored results)."""
from datetime import datetime, time, timedelta

from django.db.models import Avg, Count, Max, Min, Q
from django.db.models.functions import TruncDate
from django.utils import timezone

from .models import Status, UrlResult


def uptime_map(checks, hours):
    """{check_id: uptime %} over the window; degraded counts as available."""
    since = timezone.now() - timedelta(hours=hours)
    rows = (UrlResult.objects.filter(url_check__in=checks, checked_at__gte=since).values("url_check_id")
            .annotate(total=Count("id"), up=Count("id", filter=~Q(status=Status.DOWN))))
    return {r["url_check_id"]: 100.0 * r["up"] / r["total"] for r in rows if r["total"]}


def overall_uptime(checks, hours):
    since = timezone.now() - timedelta(hours=hours)
    agg = UrlResult.objects.filter(url_check__in=checks, checked_at__gte=since).aggregate(
        total=Count("id"), up=Count("id", filter=~Q(status=Status.DOWN)))
    return 100.0 * agg["up"] / agg["total"] if agg["total"] else None


def response_trend(checks, hours=24, buckets=48):
    """Average/min/max response time across all checks per time bucket. Missing buckets are None (not 0)."""
    now = timezone.now()
    size = hours * 3600 / buckets
    start = now - timedelta(hours=hours)
    # One aggregate query: avg/min/max per bucket [start + i*size, start + (i+1)*size), computed by the database.
    edges = [start + timedelta(seconds=size * i) for i in range(buckets)] + [now]
    aggs = {}
    for i in range(buckets):
        q = Q(checked_at__gte=edges[i], checked_at__lt=edges[i + 1])
        aggs.update({f"a{i}": Avg("response_ms", filter=q), f"n{i}": Min("response_ms", filter=q),
                     f"x{i}": Max("response_ms", filter=q)})
    agg = UrlResult.objects.filter(url_check__in=checks, checked_at__gte=start, checked_at__lt=now,
                                   response_ms__isnull=False).aggregate(**aggs)
    labels, tips, avg, mn, mx = [], [], [], [], []
    for i in range(buckets):
        t = timezone.localtime(edges[i])
        labels.append(t.strftime("%H:%M"))
        tips.append(t.strftime("%d %b %H:%M"))
        a = agg[f"a{i}"]
        avg.append(round(a, 1) if a is not None else None)
        mn.append(agg[f"n{i}"])
        mx.append(agg[f"x{i}"])
    data = {"labels": labels, "tipLabels": tips, "unit": "ms", "series": [
        {"name": "Average", "color": "#2b4cff", "values": avg, "width": 2},
        {"name": "Minimum", "color": "#0f7a55", "values": mn},
        {"name": "Maximum", "color": "#ff5b2e", "values": mx, "area": True, "areaOpacity": 0.08},
    ]}
    data.update(axis_scale(max((v for v in mx if v is not None), default=0)))
    return data


def axis_scale(peak, max_ticks=5):
    """Tight y axis for a peak value: a round tick step (1/2/2.5/5 x 10^k) and at most max_ticks steps."""
    if not peak or peak <= 0:
        return {}
    k = 10 ** max(0, len(str(int(peak))) - 2)
    for step in (m * k * f for f in (1, 10, 100) for m in (1, 2, 2.5, 5) if m * k * f >= 10 or m != 2.5):
        n = -(-peak // step)
        if n <= max_ticks:
            return {"yMax": step * n, "yTicks": max(2, int(n))} if n >= 2 else {"yMax": step * 2, "yTicks": 2}
    return {}


def daily_history(checks, days=7):
    """Per day, how many checks were Online / Degraded / Down.
    A check counts as Down for a day if >5% of its results were down, Degraded if >5% were degraded."""
    today = timezone.localdate()
    start = today - timedelta(days=days - 1)
    # Counts per (check, local day) are aggregated by the database; only those few rows reach Python.
    rows = (UrlResult.objects.filter(url_check__in=checks, checked_at__gte=timezone.make_aware(datetime.combine(start, time.min)))
            .annotate(day=TruncDate("checked_at", tzinfo=timezone.get_current_timezone()))
            .values("url_check_id", "day").order_by()
            .annotate(total=Count("id"), dn=Count("id", filter=Q(status=Status.DOWN)),
                      dg=Count("id", filter=Q(status=Status.DEGRADED))))
    per = {}  # day -> [(total, down, degraded) per check]
    for r in rows:
        per.setdefault(r["day"], []).append((r["total"], r["dn"], r["dg"]))
    labels, online, degraded, down = [], [], [], []
    for i in range(days):
        d = start + timedelta(days=i)
        labels.append(d.strftime("%b %d"))
        o = g = x = 0
        for total, dn, dg in per.get(d, ()):
            if dn / total > 0.05:
                x += 1
            elif dg / total > 0.05:
                g += 1
            else:
                o += 1
        online.append(o or None)
        degraded.append(g or None)
        down.append(x or None)
    return {"labels": labels, "series": [
        {"name": "Online", "color": "#0f7a55", "values": online},
        {"name": "Down", "color": "#d92d20", "values": down},
        {"name": "Degraded", "color": "#e08a00", "values": degraded},
    ]}


def avg_response(checks, hours=24, offset_hours=0):
    """Mean response time over [now - offset - hours, now - offset)."""
    end = timezone.now() - timedelta(hours=offset_hours)
    qs = UrlResult.objects.filter(url_check__in=checks, checked_at__gte=end - timedelta(hours=hours), response_ms__isnull=False)
    if offset_hours:
        qs = qs.filter(checked_at__lt=end)
    return qs.aggregate(v=Avg("response_ms"))["v"]
