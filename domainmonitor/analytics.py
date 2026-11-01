"""Uptime, downtime and response-time statistics computed from stored DomainCheck rows.

Everything here reads the database only; nothing is estimated or filled in. A window with no checks
yields None (shown as "–"), never 0 or 100.
"""
from collections import defaultdict
from datetime import datetime, time, timedelta

from django.db.models import Case, Count, F, IntegerField, Max, Q, Sum, Value, When, Window
from django.db.models.expressions import RowRange
from django.db.models.functions import Lag
from django.utils import timezone

from .models import DomainCheck

WINDOWS = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}


# ----------------------------------------------------------------------------------- uptime
def uptime_between(domain_ids, start, end):
    """{domain_id: uptime %} from the checks in [start, end)."""
    rows = (DomainCheck.objects.filter(domain_id__in=list(domain_ids), checked_at__gte=start, checked_at__lt=end)
            .values("domain_id").annotate(total=Count("id"), up=Count("id", filter=Q(up=True))).order_by())
    return {r["domain_id"]: 100.0 * r["up"] / r["total"] for r in rows if r["total"]}


def uptime_windows(domain_ids, now=None):
    """{domain_id: {"24h": %, "7d": %, "30d": %, "checks_30d": n}} – a missing key means no checks in that window."""
    now = now or timezone.now()
    ids = list(domain_ids)
    out = defaultdict(dict)
    for key, span in WINDOWS.items():
        for pk, value in uptime_between(ids, now - span, now + timedelta(seconds=1)).items():
            out[pk][key] = value
    counts = (DomainCheck.objects.filter(domain_id__in=ids, checked_at__gte=now - WINDOWS["30d"])
              .values("domain_id").annotate(n=Count("id")).order_by())
    for r in counts:
        out[r["domain_id"]]["checks_30d"] = r["n"]
    return out


def mean(values):
    values = [v for v in values if v is not None]
    return sum(values) / len(values) if values else None


def daily_availability(domain_ids, days, today=None):
    """Availability per local calendar day for the last `days` days (today included).

    Returns (dates, overall, per_domain) where overall[i] is the share of successful checks across all
    domains on dates[i] and per_domain[pk][i] = {"pct": %, "n": checks} (pct None when there were no checks).
    Counted in the database (one row per domain and day), so a 30-day window stays fast with many checks.
    """
    today = today or timezone.localdate()
    dates = [today - timedelta(days=days - 1 - i) for i in range(days)]
    ids = list(domain_ids)
    start = timezone.make_aware(datetime.combine(dates[0], time.min))
    end = timezone.make_aware(datetime.combine(today + timedelta(days=1), time.min))
    per = {pk: [[0, 0] for _ in dates] for pk in ids}
    tot = [[0, 0] for _ in dates]
    # day index from plain range comparisons (local midnights computed here), so no per-row date conversion
    bounds = [timezone.make_aware(datetime.combine(d + timedelta(days=1), time.min)) for d in dates]
    day = Case(*[When(checked_at__lt=b, then=Value(i)) for i, b in enumerate(bounds)], output_field=IntegerField())
    rows = (DomainCheck.objects.filter(domain_id__in=ids, checked_at__gte=start, checked_at__lt=end)
            .annotate(day=day).values("domain_id", "day")
            .annotate(n=Count("id"), up=Count("id", filter=Q(up=True))).order_by())
    for r in rows:
        i = r["day"]
        if i is None or r["domain_id"] not in per:
            continue
        for cell in (per[r["domain_id"]][i], tot[i]):
            cell[0] += r["n"]
            cell[1] += r["up"]
    pct = lambda c: round(100.0 * c[1] / c[0], 2) if c[0] else None  # noqa: E731
    overall = [pct(c) for c in tot]
    per_domain = {pk: [{"pct": pct(c), "n": c[0], "date": dates[i]} for i, c in enumerate(cells)] for pk, cells in per.items()}
    return dates, overall, per_domain


def downtime_periods(domain_ids, since, now=None):
    """Contiguous runs of failed checks per domain since `since`.

    A period starts at the first failed check and ends at the first successful check after it; when no
    successful check followed, the period is ongoing and its duration runs until `now`. Newest first.

    Only the state changes are read: a window function compares every check with the previous one of the
    same domain in the database, so the cost does not grow with the number of successful checks.
    """
    now = now or timezone.now()
    ids = list(domain_ids)
    if not ids:
        return []
    part, order = [F("domain_id")], [F("checked_at").asc(), F("id").asc()]
    failed_so_far = Sum(Case(When(up=False, then=1), default=0, output_field=IntegerField()))
    changes = (DomainCheck.objects.filter(domain_id__in=ids, checked_at__gte=since)
               .annotate(prev_up=Window(Lag("up"), partition_by=part, order_by=order),
                         prev_at=Window(Lag("checked_at"), partition_by=part, order_by=order),
                         fails=Window(failed_so_far, partition_by=part, order_by=order, frame=RowRange(start=None, end=0)))
               .filter(Q(up=False, prev_up__isnull=True) | Q(up=False, prev_up=True) | Q(up=True, prev_up=False))
               .values_list("domain_id", "checked_at", "up", "message", "fails", "prev_at")
               .order_by("domain_id", "checked_at", "id"))
    totals = {r["domain_id"]: r for r in (DomainCheck.objects.filter(domain_id__in=ids, checked_at__gte=since, up=False)
                                          .values("domain_id").annotate(n=Count("id"), last=Max("checked_at")).order_by())}
    out, current = [], {}
    for pk, at, up, message, fails, prev_at in changes:
        if not up:
            current[pk] = {"domain_id": pk, "start": at, "end": None, "message": message, "fails_before": fails - 1}
        elif pk in current:
            p = current.pop(pk)
            p.update(end=at, failed=fails - p.pop("fails_before"), last_failed=prev_at)
            out.append(p)
    for pk, p in current.items():
        t = totals.get(pk, {"n": p["fails_before"] + 1, "last": p["start"]})
        p.update(failed=t["n"] - p.pop("fails_before"), last_failed=t["last"])
        out.append(p)
    for p in out:
        p["ongoing"] = p["end"] is None
        p["duration"] = (p["end"] or now) - p["start"]
    out.sort(key=lambda p: p["start"], reverse=True)
    return out


def summarize_periods(periods):
    """{domain_id: {"count", "total", "longest", "last"}} for a list from downtime_periods()."""
    out = {}
    for p in periods:
        s = out.setdefault(p["domain_id"], {"count": 0, "total": timedelta(0), "longest": timedelta(0), "last": None})
        s["count"] += 1
        s["total"] += p["duration"]
        s["longest"] = max(s["longest"], p["duration"])
        if s["last"] is None or p["start"] > s["last"]["start"]:
            s["last"] = p
    return out


def fmt_duration(td):
    """Compact human duration: 45s, 12m, 3h 05m, 2d 4h."""
    if td is None:
        return "–"
    s = int(td.total_seconds())
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m"
    if s < 86400:
        return f"{s // 3600}h {s % 3600 // 60:02d}m"
    return f"{s // 86400}d {s % 86400 // 3600}h"


# ----------------------------------------------------------------------------------- response time
def percentile(sorted_values, p):
    """Linear-interpolated percentile (same as numpy's default) of an already sorted list."""
    if not sorted_values:
        return None
    if len(sorted_values) == 1:
        return sorted_values[0]
    k = (len(sorted_values) - 1) * p / 100.0
    lo = int(k)
    hi = min(lo + 1, len(sorted_values) - 1)
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (k - lo)


def describe(values):
    values = sorted(values)
    if not values:
        return {"n": 0, "p50": None, "p95": None, "max": None, "avg": None}
    return {"n": len(values), "p50": percentile(values, 50), "p95": percentile(values, 95), "max": values[-1],
            "avg": sum(values) / len(values)}


def response_samples(domain_ids, start, end):
    return (DomainCheck.objects.filter(domain_id__in=list(domain_ids), checked_at__gte=start, checked_at__lt=end,
                                       response_ms__isnull=False)
            .values_list("domain_id", "checked_at", "response_ms").order_by())


def response_stats(domain_ids, start, end):
    """({domain_id: describe()}, overall describe(), raw rows) for successful checks in [start, end)."""
    rows = list(response_samples(domain_ids, start, end))
    per = defaultdict(list)
    for pk, _at, ms in rows:
        per[pk].append(ms)
    return {pk: describe(v) for pk, v in per.items()}, describe([r[2] for r in rows]), rows


def bucket_series(rows, start, bucket, n):
    """p50/p95 per time bucket: two lists of length n (None for empty buckets)."""
    acc = defaultdict(list)
    size = bucket.total_seconds()
    for _pk, at, ms in rows:
        i = int((at - start).total_seconds() // size)
        if 0 <= i < n:
            acc[i].append(ms)
    p50, p95 = [], []
    for i in range(n):
        vals = sorted(acc.get(i, []))
        p50.append(round(percentile(vals, 50), 1) if vals else None)
        p95.append(round(percentile(vals, 95), 1) if vals else None)
    return p50, p95


def change_pct(cur, prev):
    if cur is None or not prev:
        return None
    return round(100.0 * (cur - prev) / prev, 1)
