"""Prometheus scrape targets (/api/v1/targets) and server KPIs."""
import logging

from django.core.cache import cache

from core import prometheus

from . import promapi

from .fmt import finite, parse_ts

log = logging.getLogger("linkedeye.telemetry")

CACHE_SECONDS = 30
HEALTH_ORDER = {"down": 0, "unknown": 1, "up": 2}
HIDDEN_LABELS = {"job", "instance"}


def normalize(t):
    labels = t.get("labels") or {}
    health = str(t.get("health") or "unknown").lower()
    if health not in HEALTH_ORDER:
        health = "unknown"
    dur = t.get("lastScrapeDuration")
    try:
        dur = float(dur) if dur is not None else None
    except (TypeError, ValueError):
        dur = None
    last = parse_ts(t.get("lastScrape"))
    if last is None and not dur:
        dur = None  # never scraped: Prometheus reports 0 s, which is not a measurement
    return {
        "job": labels.get("job") or t.get("scrapePool") or "",
        "pool": t.get("scrapePool") or labels.get("job") or "",
        "instance": labels.get("instance", ""),
        "url": t.get("scrapeUrl") or t.get("globalUrl") or "",
        "health": health,
        "error": (t.get("lastError") or "").strip(),
        "last_scrape": last,
        "duration": dur if finite(dur) else None,
        "interval": t.get("scrapeInterval") or "",
        "labels": sorted((k, v) for k, v in labels.items() if k not in HIDDEN_LABELS),
    }


def fetch_targets(use_cache=True):
    key = "telemetry:targets:v1"
    if use_cache:
        hit = cache.get(key)
        if hit is not None:
            return hit
    rows = [normalize(t) for t in promapi.targets()]
    rows.sort(key=lambda r: (r["job"], HEALTH_ORDER[r["health"]], r["instance"]))
    cache.set(key, rows, CACHE_SECONDS)
    return rows


def jobs_summary(rows):
    jobs = {}
    for r in rows:
        j = jobs.setdefault(r["job"], {"job": r["job"], "total": 0, "up": 0, "down": 0, "unknown": 0, "durations": []})
        j["total"] += 1
        j[r["health"]] += 1
        if r["duration"] is not None:
            j["durations"].append(r["duration"])
    out = []
    for j in jobs.values():
        d = j.pop("durations")
        j["avg_duration"] = (sum(d) / len(d)) if d else None
        j["up_pct"] = 100.0 * j["up"] / j["total"] if j["total"] else 0
        j["health"] = "down" if j["down"] else "unknown" if j["unknown"] == j["total"] else "up"
        out.append(j)
    return sorted(out, key=lambda j: (HEALTH_ORDER[j["health"]], j["job"]))


def kpis(rows):
    durs = [r["duration"] for r in rows if r["duration"] is not None]
    slowest = max(rows, key=lambda r: r["duration"] or 0) if durs else None
    return {"total": len(rows), "up": sum(r["health"] == "up" for r in rows),
            "down": sum(r["health"] == "down" for r in rows), "unknown": sum(r["health"] == "unknown" for r in rows),
            "jobs": len({r["job"] for r in rows}), "avg_duration": (sum(durs) / len(durs)) if durs else None,
            "slowest": slowest}


SERVER_QUERIES = {
    "head_series": "sum(prometheus_tsdb_head_series)",
    "ingest_rate": "sum(rate(prometheus_tsdb_head_samples_appended_total[5m]))",
}


def server_stats(use_cache=True):
    """Prometheus' own self-metrics and active rule alerts. Missing pieces are None (never fabricated).

    Failures here are not fatal for the page: returns the stats it could get plus an error string."""
    key = "telemetry:promstats:v1"
    if use_cache:
        hit = cache.get(key)
        if hit is not None:
            return hit
    out = {"head_series": None, "ingest_rate": None, "rule_alerts_firing": None, "rule_alerts_pending": None, "error": ""}
    try:
        for k, q in SERVER_QUERIES.items():
            rows = promapi.query(q)
            if rows and finite(rows[0].get("value")):
                out[k] = rows[0]["value"]
        alerts = promapi.alerts()
        out["rule_alerts_firing"] = sum(1 for a in alerts if a.get("state") == "firing")
        out["rule_alerts_pending"] = sum(1 for a in alerts if a.get("state") == "pending")
    except prometheus.PrometheusError as e:
        out["error"] = str(e)
    cache.set(key, out, CACHE_SECONDS)
    return out
