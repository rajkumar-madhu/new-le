from django.shortcuts import render

from core import prometheus
from core.access import require

from .. import palette as pal, targets as svc
from .common import csv_response, matches, paginate, perms, prom_context, query_without_page

HEALTHS = [("up", "Up"), ("down", "Down"), ("unknown", "Unknown")]


@require("view")
def prometheus_targets(request):
    ctx = {**prom_context(), **perms(request), "error": ""}
    refresh = request.GET.get("refresh") == "1"
    rows, stats = [], None
    if ctx["prom_configured"]:
        try:
            rows = svc.fetch_targets(use_cache=not refresh)
        except prometheus.PrometheusError as e:
            ctx["error"] = str(e)
        if not ctx["error"]:
            stats = svc.server_stats(use_cache=not refresh)
    jobs = svc.jobs_summary(rows)
    kpis = svc.kpis(rows)
    q, health, job = request.GET.get("q", ""), request.GET.get("health", ""), request.GET.get("job", "")
    shown = [r for r in rows if matches(q, r["instance"], r["url"], r["job"], r["error"], *(v for _k, v in r["labels"]))
             and (not health or r["health"] == health) and (not job or r["job"] == job)]
    if request.GET.get("format") == "csv":
        return csv_response("prometheus-targets.csv",
                            ["job", "instance", "scrape_url", "health", "last_scrape", "duration_s", "error", "labels"],
                            [[r["job"], r["instance"], r["url"], r["health"], r["last_scrape"].isoformat() if r["last_scrape"] else "",
                              "" if r["duration"] is None else round(r["duration"], 4), r["error"],
                              " ".join(f"{k}={v}" for k, v in r["labels"])] for r in shown])
    page = paginate(request, shown, default=50)
    # group header rows for the current page
    groups, counts = [], {j["job"]: j for j in jobs}
    for r in page:
        if not groups or groups[-1]["job"] != r["job"]:
            groups.append({"job": r["job"], "summary": counts.get(r["job"]), "rows": []})
        groups[-1]["rows"].append(r)
    ctx.update({
        "kpis": kpis, "stats": stats, "jobs": jobs, "page": page, "groups": groups, "healths": HEALTHS,
        "down_targets": [r for r in rows if r["health"] == "down"][:8],
        "query": query_without_page(request, "refresh"), "filtered": bool(q or health or job),
        "donut": {"segments": [
            {"label": "Up", "value": kpis["up"], "color": pal.OK},
            {"label": "Down", "value": kpis["down"], "color": pal.CRIT},
            {"label": "Unknown", "value": kpis["unknown"], "color": pal.STONE_LIGHT}],
            "center": {"value": str(kpis["total"]), "label": "Targets"}},
    })
    return render(request, "telemetry/prometheus.html", ctx)
