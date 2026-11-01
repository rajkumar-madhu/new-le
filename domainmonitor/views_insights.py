"""Domains › Uptime Monitoring, Performance, Security and Export Reports.

All numbers come from stored DomainCheck / DomainSecurityScan rows; windows without data show "–".
"""
import json
import math
from collections import Counter
from datetime import timedelta

from django.conf import settings
from django.contrib import messages
from django.core.paginator import Paginator
from django.core.serializers.json import DjangoJSONEncoder
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_POST

from core.access import require
from core.audit import audit

from . import analytics, security
from .models import GRADES, DOMAIN_TYPES
from .views import SSL_STATES, SafeCsvWriter, _filter, _per_page, _query, _render, _scope, can_operate_on, mark_operable

UPTIME_DAYS = {"7": ("Last 7 days", 1), "14": ("Last 14 days", 2), "30": ("Last 30 days", 5)}
# window key -> (label, span, bucket, label every n buckets, label format)
PERF_WINDOWS = {
    "6": ("Last 6 hours", timedelta(hours=6), timedelta(minutes=15), 4, "%H:%M"),
    "24": ("Last 24 hours", timedelta(hours=24), timedelta(hours=1), 3, "%H:%M"),
    "168": ("Last 7 days", timedelta(days=7), timedelta(hours=6), 4, "%b %d"),
    "720": ("Last 30 days", timedelta(days=30), timedelta(days=1), 5, "%b %d"),
}
GRADE_COLORS = {"A": "#16a34a", "B": "#65a30d", "C": "#eab308", "D": "#f59e0b", "E": "#ea580c", "F": "#dc2626"}
GRADE_TONES = {"A": "ok", "B": "ok", "C": "warn", "D": "warn", "E": "crit", "F": "crit"}
REGRESSION_PCT = 20.0
MAX_REPORT_ROWS = 2000
MAX_MANUAL_SCANS = 100


def _csv_response(filename):
    resp = HttpResponse(content_type="text/csv")
    resp["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp, SafeCsvWriter(resp)


def _fmt_pct(v):
    return "" if v is None else f"{v:.2f}"


def _iso(dt):
    return dt.isoformat() if dt else ""


def _filter_context(request, scope):
    return {
        "sites": scope.exclude(site_key="").order_by("site_key").values_list("site_key", flat=True).distinct(),
        "types": sorted(set(scope.order_by().values_list("domain_type", flat=True).distinct()) | set(DOMAIN_TYPES)),
    }


# ======================================================================================= uptime
def uptime(request):
    scope = _scope(request).filter(is_active=True)
    domains = list(_filter(scope, request))
    ids = [d.pk for d in domains]
    now = timezone.now()
    key = request.GET.get("days") if request.GET.get("days") in UPTIME_DAYS else "30"
    days = int(key)
    win = analytics.uptime_windows(ids, now)
    dates, overall, per_day = analytics.daily_availability(ids, days)
    periods = analytics.downtime_periods(ids, now - timedelta(days=days), now)
    summary = analytics.summarize_periods(periods)
    by_id = {d.pk: d for d in domains}
    for d in domains:
        w = win.get(d.pk, {})
        d.u24, d.u7, d.u30, d.checks30 = w.get("24h"), w.get("7d"), w.get("30d"), w.get("checks_30d", 0)
        d.daily = per_day.get(d.pk, [])
        s = summary.get(d.pk)
        d.down_count = s["count"] if s else 0
        d.down_total = s["total"] if s else timedelta(0)
        d.down_total_label = analytics.fmt_duration(d.down_total) if s else "–"
        d.last_down = s["last"] if s else None
    for p in periods:
        p["domain"] = by_id.get(p["domain_id"])
        p["duration_label"] = analytics.fmt_duration(p["duration"])

    if request.GET.get("format") == "csv":
        if request.GET.get("what") == "downtime":
            resp, w = _csv_response("domain-downtime.csv")
            w.writerow(["hostname", "site", "started", "ended", "ongoing", "duration_seconds", "failed_checks", "message"])
            for p in periods:
                w.writerow([p["domain"].hostname, p["domain"].site_key, _iso(p["start"]), _iso(p["end"]),
                            "yes" if p["ongoing"] else "no", int(p["duration"].total_seconds()), p["failed"], p["message"]])
            return resp
        resp, w = _csv_response("domain-uptime.csv")
        w.writerow(["hostname", "site", "type", "status", "uptime_24h", "uptime_7d", "uptime_30d", "checks_30d",
                    f"downtime_periods_{days}d", f"downtime_seconds_{days}d"])
        for d in domains:
            w.writerow([d.hostname, d.site_key, d.domain_type, d.status, _fmt_pct(d.u24), _fmt_pct(d.u7), _fmt_pct(d.u30),
                        d.checks30, d.down_count, int(d.down_total.total_seconds())])
        return resp

    sort = request.GET.get("sort", "")
    if sort == "uptime":
        domains.sort(key=lambda d: (d.u30 is None, d.u30 if d.u30 is not None else 0, d.hostname))
    elif sort == "downtime":
        domains.sort(key=lambda d: (-d.down_total.total_seconds(), d.hostname))
    page = Paginator(domains, _per_page(request)).get_page(request.GET.get("page"))

    known = [v for v in overall if v is not None]
    y_min = min(99.5, max(0.0, math.floor(2 * (min(known) - 0.5)) / 2)) if known else 95.0
    chart = {"labels": [d.strftime("%b %d") for d in dates], "tipLabels": [d.strftime("%a %d %b %Y") for d in dates],
             "unit": "%", "yMin": y_min, "yMax": 100, "yTicks": 4, "xLabelEvery": UPTIME_DAYS[key][1],
             "series": [{"name": "Availability", "color": "#16a34a", "area": True, "areaOpacity": 0.25, "width": 1.8,
                         "values": overall}]}
    resolved = [p["duration"] for p in periods if not p["ongoing"]]
    longest = max(periods, key=lambda p: p["duration"]) if periods else None
    total_down = sum((p["duration"] for p in periods), timedelta(0))
    k = {
        "u24": analytics.mean(d.u24 for d in domains), "u7": analytics.mean(d.u7 for d in domains),
        "u30": analytics.mean(d.u30 for d in domains),
        "incidents": len(periods), "ongoing": sum(1 for p in periods if p["ongoing"]),
        "affected": len(summary), "total_down": analytics.fmt_duration(total_down) if periods else "–",
        "longest": longest, "mttr": analytics.fmt_duration(sum(resolved, timedelta(0)) / len(resolved)) if resolved else "–",
        "down_now": sum(1 for d in domains if d.status == "down"),
    }
    return _render(request, "domainmonitor/uptime.html", {
        "tab": "uptime", "crumb": "Uptime Monitoring", "page": page, "query": _query(request),
        "sort_query": _query(request, "sort"), "sort": sort, "k": k, "chart": chart,
        "days_key": key, "days": days, "day_ranges": [(x, v[0]) for x, v in UPTIME_DAYS.items()],
        "day_label": UPTIME_DAYS[key][0], "dates": dates, "periods": periods[:15], "periods_total": len(periods),
        "total": len(domains), **_filter_context(request, scope),
    })


# ======================================================================================= performance
def _aligned_window(now, span, bucket):
    """[start, end) ending at the bucket boundary after `now` (local time), so axis labels are round."""
    local = timezone.localtime(now)
    midnight = local.replace(hour=0, minute=0, second=0, microsecond=0)
    b = bucket.total_seconds()
    end = midnight + timedelta(seconds=((local - midnight).total_seconds() // b + 1) * b)
    return end - span, end


def _trend(d):
    """(label, chip tone, text tone) of a domain's p95 change vs the previous window."""
    if not d.cur["n"]:
        return "No data", "mute", "t-mute"
    if d.change is None:
        return "New", "mute", "t-mute"
    if d.change >= REGRESSION_PCT:
        return "Regressed", "crit", "t-crit"
    if d.change <= -REGRESSION_PCT:
        return "Improved", "ok", "t-ok"
    return "Stable", "teal", ""


def _window_links(request):
    links = []
    for x, v in PERF_WINDOWS.items():
        q = _query(request, "window")
        q["window"] = x
        links.append((x, v[0], q.urlencode()))
    return links


def performance(request):
    scope = _scope(request).filter(is_active=True)
    domains = list(_filter(scope, request))
    ids = [d.pk for d in domains]
    key = request.GET.get("window") if request.GET.get("window") in PERF_WINDOWS else "24"
    label, span, bucket, every, fmt = PERF_WINDOWS[key]
    start, end = _aligned_window(timezone.now(), span, bucket)
    prev_start = start - span
    cur, cur_all, rows = analytics.response_stats(ids, start, end)
    prev, prev_all, prev_rows = analytics.response_stats(ids, prev_start, start)
    empty = analytics.describe([])
    for d in domains:
        d.cur, d.prev = cur.get(d.pk, empty), prev.get(d.pk, empty)
        d.change = analytics.change_pct(d.cur["p95"], d.prev["p95"])
        d.p50_change = analytics.change_pct(d.cur["p50"], d.prev["p50"])
        d.trend = _trend(d)

    sort = request.GET.get("sort") or "-p95"
    keys = {"-p95": "p95", "-p50": "p50", "-max": "max", "-avg": "avg"}
    if sort in keys:
        domains.sort(key=lambda d: (d.cur[keys[sort]] is None, -(d.cur[keys[sort]] or 0), d.hostname))
    elif sort == "-change":
        domains.sort(key=lambda d: (d.change is None, -(d.change or 0), d.hostname))
    elif sort == "hostname":
        domains.sort(key=lambda d: d.hostname)

    if request.GET.get("format") == "csv":
        resp, w = _csv_response("domain-performance.csv")
        w.writerow(["hostname", "site", "window", "samples", "p50_ms", "p95_ms", "max_ms", "avg_ms", "prev_samples",
                    "prev_p50_ms", "prev_p95_ms", "prev_max_ms", "p95_change_pct"])
        r1 = lambda v: "" if v is None else round(v, 1)  # noqa: E731
        for d in domains:
            w.writerow([d.hostname, d.site_key, label, d.cur["n"], r1(d.cur["p50"]), r1(d.cur["p95"]), r1(d.cur["max"]),
                        r1(d.cur["avg"]), d.prev["n"], r1(d.prev["p50"]), r1(d.prev["p95"]), r1(d.prev["max"]),
                        "" if d.change is None else d.change])
        return resp

    n = int(span / bucket)
    p50, p95 = analytics.bucket_series(rows, start, bucket, n)
    _pp50, prev_p95 = analytics.bucket_series(prev_rows, prev_start, bucket, n)
    times = [timezone.localtime(start + bucket * i) for i in range(n)]
    chart = {"labels": [t.strftime(fmt) for t in times], "tipLabels": [t.strftime("%d %b %H:%M") for t in times],
             "unit": "ms", "xLabelEvery": every, "yTicks": 5,
             "series": [{"name": "p95", "color": "#7c3aed", "values": p95, "width": 1.8},
                        {"name": "p50", "color": "#1565f0", "values": p50, "area": True, "areaOpacity": 0.12, "width": 1.8},
                        {"name": "p95 (previous window)", "color": "#94a3b8", "values": prev_p95, "dash": "4 3", "width": 1.4}]}
    ranked = [d for d in domains if d.cur["p95"] is not None]
    slowest = sorted(ranked, key=lambda d: -d.cur["p95"])[:5]
    top = slowest[0].cur["p95"] if slowest else 0
    for d in slowest:
        d.bar = round(100.0 * d.cur["p95"] / top, 1) if top else 0
    page = Paginator(domains, _per_page(request)).get_page(request.GET.get("page"))
    k = {
        "cur": cur_all, "prev": prev_all,
        "p50_change": analytics.change_pct(cur_all["p50"], prev_all["p50"]),
        "p95_change": analytics.change_pct(cur_all["p95"], prev_all["p95"]),
        "max_change": analytics.change_pct(cur_all["max"], prev_all["max"]),
        "samples_change": analytics.change_pct(cur_all["n"], prev_all["n"]),
        "regressed": sum(1 for d in domains if d.change is not None and d.change >= REGRESSION_PCT),
        "improved": sum(1 for d in domains if d.change is not None and d.change <= -REGRESSION_PCT),
        "no_data": sum(1 for d in domains if not d.cur["n"]),
    }
    return _render(request, "domainmonitor/performance.html", {
        "tab": "performance", "crumb": "Performance", "page": page, "query": _query(request),
        "sort_query": _query(request, "sort"), "sort": sort, "k": k, "chart": chart, "slowest": slowest,
        "window": key, "window_label": label, "windows": _window_links(request),
        "start": start, "end": end, "prev_start": prev_start, "regression_pct": int(REGRESSION_PCT),
        "total": len(domains), **_filter_context(request, scope),
    })


# ======================================================================================= security
def _attach_scans(domains):
    latest = security.latest_scans([d.pk for d in domains])
    for d in domains:
        d.scan = latest.get(d.pk)
        d.grade = d.scan.grade if d.scan else None
        by_key = {f["key"]: f for f in d.scan.findings} if d.scan else {}
        d.header_checks = [(key, security.CHECKS[key][0], by_key.get(key)) for key in security.HEADER_CHECKS]
    return domains


def _recommendations(domains):
    """Failing checks across the latest scans, most severe and most widespread first."""
    agg = {}
    for d in domains:
        if not d.scan or not d.scan.grade:
            continue
        for f in d.scan.findings:
            if f.get("passed"):
                continue
            label, severity, weight, rec = security.CHECKS.get(f["key"], (f.get("label", f["key"]), "low", 0, ""))
            a = agg.setdefault(f["key"], {"key": f["key"], "label": label, "severity": severity, "recommendation": rec,
                                          "domains": []})
            a["domains"].append(d)
    out = list(agg.values())
    out.sort(key=lambda a: (-security.SEVERITY_RANK.get(a["severity"], 0), -len(a["domains"]), a["label"]))
    return out


def security_page(request):
    scope = _scope(request).filter(is_active=True)
    domains = _attach_scans(list(_filter(scope, request)))
    counts = Counter(d.grade for d in domains if d.grade)
    unscanned = sum(1 for d in domains if not d.scan)
    failed = sum(1 for d in domains if d.scan and not d.scan.grade)
    grade = request.GET.get("grade", "")
    shown = domains
    if grade in GRADES:
        shown = [d for d in domains if d.grade == grade]
    elif grade == "none":
        shown = [d for d in domains if not d.scan]
    elif grade == "error":
        shown = [d for d in domains if d.scan and not d.scan.grade]
    sort = request.GET.get("sort", "")
    if sort == "grade":
        shown = sorted(shown, key=lambda d: (not d.grade, d.grade or "", d.hostname))
    elif sort == "-grade":
        shown = sorted(shown, key=lambda d: (not d.grade, -ord(d.grade) if d.grade else 0, d.hostname))

    if request.GET.get("format") == "csv":
        resp, w = _csv_response("domain-security.csv")
        w.writerow(["hostname", "site", "grade", "score", "scanned_at", "tls_version", "cipher", "cert_issuer", "cert_days_left",
                    "https_redirect", "hsts", "csp", "x_frame_options", "x_content_type_options", "referrer_policy",
                    "permissions_policy", "server", "failed_checks", "error"])
        for d in shown:
            s = d.scan
            if not s:
                w.writerow([d.hostname, d.site_key] + [""] * 16 + ["not scanned"])
                continue
            w.writerow([d.hostname, d.site_key, s.grade, "" if s.score is None else s.score, _iso(s.scanned_at), s.tls_version,
                        s.cipher, s.cert_issuer, "" if s.cert_days_left is None else s.cert_days_left,
                        "" if s.https_redirect is None else ("yes" if s.https_redirect else "no"), s.hsts, s.csp,
                        s.x_frame_options, s.x_content_type_options, s.referrer_policy, s.permissions_policy, s.server,
                        "; ".join(f["label"] for f in s.failed), s.error])
        return resp

    scans = [d.scan for d in domains if d.scan and d.scan.grade]
    graded = len(scans)
    selected = None
    sel = request.GET.get("selected")
    if sel and sel.isdigit():
        selected = next((d for d in domains if d.pk == int(sel)), None)
        if selected is None:
            # outside the current filter: still show it when visible; an unknown or out-of-scope pk is ignored
            found = scope.filter(pk=int(sel)).first()
            selected = _attach_scans([found])[0] if found else None
    detail = {}
    if selected:
        history = list(selected.security_scans.all()[:10])
        fs = selected.scan.findings if selected.scan else []
        detail = {"history": history, "failed_findings": [f for f in fs if not f.get("passed")],
                  "passed_findings": [f for f in fs if f.get("passed")]}
    page = Paginator(shown, _per_page(request)).get_page(request.GET.get("page"))
    mark_operable(request.user, list(page) + ([selected] if selected else []))
    legend = [{"label": f"Grade {g}", "grade": g, "color": GRADE_COLORS[g], "n": counts.get(g, 0)} for g in GRADES]
    if unscanned:
        legend.append({"label": "Not scanned", "grade": "none", "color": "#cbd5e1", "n": unscanned})
    if failed:
        legend.append({"label": "Scan failed", "grade": "error", "color": "#64748b", "n": failed})
    total = len(domains)
    for x in legend:
        x["pct"] = 100.0 * x["n"] / total if total else 0
    k = {
        "total": total, "graded": graded, "unscanned": unscanned, "failed": failed,
        "avg_score": analytics.mean(s.score for s in scans),
        "good": sum(1 for s in scans if s.grade in "AB"),
        "good_pct": round(100.0 * sum(1 for s in scans if s.grade in "AB") / graded, 1) if graded else None,
        "hsts_missing": sum(1 for s in scans if s.finding("hsts") and not s.finding("hsts")["passed"]),
        "cert_soon": sum(1 for s in scans if s.cert_days_left is not None and s.cert_days_left < security.CERT_WARN_DAYS),
        "last": max((d.scan.scanned_at for d in domains if d.scan), default=None),
    }
    return _render(request, "domainmonitor/security.html", {
        "tab": "security", "crumb": "Security", "page": page, "query": _query(request),
        "grade_query": _query(request, "grade"), "sort_query": _query(request, "sort"), "sort": sort,
        "grade": grade, "grades": GRADES, "grade_tones": GRADE_TONES, "counts": counts, "legend": legend,
        "donut": {"segments": [{"label": x["label"], "value": x["n"], "color": x["color"]} for x in legend],
                  "center": {"value": str(graded), "label": "Graded"}, "thickness": 24},
        "k": k, "recommendations": _recommendations(domains)[:8], "selected": selected, **detail,
        "header_labels": [(key, security.CHECKS[key][0]) for key in security.HEADER_CHECKS],
        "scan_every_h": int(security.SCAN_EVERY.total_seconds() // 3600), **_filter_context(request, scope),
    })


@require_POST
@require("operate")
def security_scan(request, pk):
    d = get_object_or_404(_scope(request).filter(is_active=True), pk=pk)
    if not can_operate_on(request.user, d.site_key):
        messages.error(request, f"You do not have operator rights on {d.site_key}.")
        return redirect(f"{reverse('domains:security')}?selected={d.pk}#scan-detail")
    scan = security.run_scans([d])[0]
    audit(request, "run", d, check="security_scan", grade=scan.grade, score=scan.score, error=scan.error)
    if scan.grade:
        messages.success(request, f"Scanned {d.hostname}: grade {scan.grade} ({scan.score}/100).")
    else:
        messages.warning(request, f"Could not scan {d.hostname}: {scan.error}")
    return redirect(f"{reverse('domains:security')}?selected={d.pk}#scan-detail")


@require_POST
@require("operate")
def security_scan_all(request):
    domains = [d for d in _scope(request).filter(is_active=True, monitor_enabled=True)
               if can_operate_on(request.user, d.site_key)][:MAX_MANUAL_SCANS]
    scans = security.run_scans(domains)
    graded = sum(1 for s in scans if s.grade)
    audit(request, "run", None, object_type="domainmonitor.domainsecurityscan", check="security_scan_all",
          count=len(scans), graded=graded)
    if scans:
        messages.success(request, f"Scanned {len(scans)} domain(s); {graded} graded, {len(scans) - graded} unreachable.")
    else:
        messages.info(request, "No active monitored domains to scan.")
    return redirect("domains:security")


# ======================================================================================= export reports
REPORT_COLUMNS = [
    ("hostname", "Domain"), ("site", "Site"), ("type", "Type"), ("group", "Group"), ("active", "Active"),
    ("status", "Status"), ("http_status", "HTTP"), ("response_ms", "Response (ms)"), ("dns_status", "DNS"),
    ("ip_address", "IP address"), ("ssl_status", "SSL"), ("ssl_expires_at", "SSL expires"),
    ("ssl_days_left", "SSL days left"), ("uptime_7d", "Uptime 7d (%)"), ("uptime_30d", "Uptime 30d (%)"),
    ("security_grade", "Security grade"), ("security_score", "Security score"),
    ("security_scanned_at", "Security scanned"), ("last_checked_at", "Last checked"),
]


def report_rows(domains, now=None):
    """One dict per domain with the columns of REPORT_COLUMNS (datetimes as aware datetimes)."""
    domains = list(domains)
    ids = [d.pk for d in domains]
    win = analytics.uptime_windows(ids, now)
    scans = security.latest_scans(ids)
    rows = []
    for d in domains:
        w, s = win.get(d.pk, {}), scans.get(d.pk)
        rows.append({
            "id": d.pk, "hostname": d.hostname, "site": d.site_key, "type": d.domain_type, "group": d.group,
            "active": d.is_active, "status": d.status, "http_status": d.http_status,
            "response_ms": None if d.response_ms is None else round(d.response_ms, 1),
            "dns_status": d.dns_status, "ip_address": d.ip_address, "ssl_status": d.ssl_status,
            "ssl_expires_at": d.ssl_expires_at, "ssl_days_left": d.ssl_days_left,
            "uptime_7d": None if w.get("7d") is None else round(w["7d"], 3),
            "uptime_30d": None if w.get("30d") is None else round(w["30d"], 3),
            "security_grade": (s.grade or None) if s else None, "security_score": s.score if s else None,
            "security_scanned_at": s.scanned_at if s else None, "last_checked_at": d.last_checked_at,
        })
    return rows


def export_reports(request):
    scope = _scope(request)
    params = request.GET.copy()
    if "active" not in params:
        params["active"] = "1"   # active domains unless "All" is chosen
    request.GET = params
    qs = _filter(scope, request).order_by("site_key", "hostname")
    total = qs.count()
    now = timezone.now()
    rows = report_rows(qs[:MAX_REPORT_ROWS], now)
    filters = {k: v for k, v in request.GET.items() if k in ("q", "site", "type", "status", "ssl", "dns", "group", "active") and v}
    fmt = request.GET.get("format")
    stamp = timezone.localtime(now).strftime("%Y%m%d-%H%M")
    if fmt in ("csv", "json"):
        audit(request, "export", None, object_type="domainmonitor.domain", format=fmt, rows=len(rows), filters=filters)
    if fmt == "csv":
        resp, w = _csv_response(f"domains-report-{stamp}.csv")
        w.writerow([c for c, _ in REPORT_COLUMNS])
        for r in rows:
            out = []
            for c, _ in REPORT_COLUMNS:
                v = r[c]
                out.append("" if v is None else ("yes" if v is True else "no" if v is False else
                                                 v.isoformat() if hasattr(v, "isoformat") else v))
            w.writerow(out)
        return resp
    if fmt == "json":
        body = {"generated_at": now, "tenant": settings.LINKEDEYE_TENANT, "filters": filters, "count": len(rows),
                "total": total, "truncated": total > len(rows), "columns": [c for c, _ in REPORT_COLUMNS], "results": rows}
        resp = HttpResponse(json.dumps(body, cls=DjangoJSONEncoder, indent=2), content_type="application/json")
        resp["Content-Disposition"] = f'attachment; filename="domains-report-{stamp}.json"'
        return resp

    up = [r for r in rows if r["status"] == "up"]
    grades = Counter(r["security_grade"] for r in rows if r["security_grade"])
    k = {
        "total": len(rows), "up": len(up), "down": sum(1 for r in rows if r["status"] == "down"),
        "unknown": sum(1 for r in rows if r["status"] not in ("up", "down")),
        "dns_failed": sum(1 for r in rows if r["dns_status"] == "Failed"),
        "ssl_attention": sum(1 for r in rows if r["ssl_status"] in ("Expiring", "Expired", "Invalid")),
        "u7": analytics.mean(r["uptime_7d"] for r in rows), "u30": analytics.mean(r["uptime_30d"] for r in rows),
        "grades": [(g, grades.get(g, 0), GRADE_TONES[g]) for g in GRADES],
        "unscanned": sum(1 for r in rows if not r["security_grade"]),
    }
    query = _query(request)
    return _render(request, "domainmonitor/export_reports.html", {
        "tab": "reports", "crumb": "Export Reports", "rows": rows, "k": k, "now": now, "total": total,
        "truncated": total > len(rows), "query": query, "filters": filters, "ssl_states": SSL_STATES,
        "filter_label": ", ".join(f"{key} = {v}" for key, v in filters.items() if key != "active"),
        "grade_tones": GRADE_TONES, "active": request.GET.get("active"), **_filter_context(request, scope),
    })
