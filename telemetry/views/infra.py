from django.http import Http404
from django.shortcuts import render

from core import prometheus
from core.access import require, scope_by_site, visible_sites

from .. import hosts as svc
from ..fmt import finite, human_duration, human_rate
from ..models import Alert
from .common import csv_response, matches, paginate, perms, prom_context, query_without_page

HEALTH_CHOICES = [("healthy", "Healthy"), ("warning", "Warning"), ("critical", "Critical"), ("down", "Down"),
                  ("unknown", "No data")]


def _site_ok(user, site, selected=""):
    if selected and site != selected:
        return False
    sites = visible_sites(user)
    return sites is None or site in ("", "All Sites") or site in sites


def _attach_cmdb(hosts):
    cis = svc.cmdb_map([h["instance"] for h in hosts])
    for h in hosts:
        ci = cis.get(h["instance"])
        h["ci"] = ci
        h["ci_name"] = ci.name if ci is not None else ""
        h["ci_url"] = svc.ci_url(ci)
        h["site"] = (getattr(ci, "site", "") or "") if ci is not None else ""
    return hosts


@require("view")
def infrastructure(request):
    ctx = {**prom_context(), **perms(request), "error": "", "spark_error": ""}
    refresh = request.GET.get("refresh") == "1"
    hosts, sparks = [], {}
    if ctx["prom_configured"]:
        try:
            hosts = [dict(h) for h in svc.fetch_hosts(use_cache=not refresh)]
        except prometheus.PrometheusError as e:
            ctx["error"] = str(e)
        if hosts:
            try:
                sparks = svc.cpu_sparklines(use_cache=not refresh)
            except prometheus.PrometheusError as e:
                ctx["spark_error"] = str(e)
    _attach_cmdb(hosts)
    site = request.GET.get("site", "")
    hosts = [h for h in hosts if _site_ok(request.user, h["site"], site)]
    summary = svc.summarize(hosts)
    jobs = sorted({h["job"] for h in hosts if h["job"]})

    q, health, job = request.GET.get("q", ""), request.GET.get("health", ""), request.GET.get("job", "")
    rows = [h for h in hosts if matches(q, h["instance"], h["ci_name"], h["job"])
            and (not health or h["health"] == health) and (not job or h["job"] == job)]

    if request.GET.get("format") == "csv":
        return csv_response("infrastructure-hosts.csv",
                            ["instance", "job", "cmdb_ci", "site", "health", "up", "cpu_pct", "memory_pct", "root_disk_pct",
                             "load1", "cores", "net_rx_Bps", "net_tx_Bps", "uptime_s"],
                            [[h["instance"], h["job"], h["ci_name"], h["site"], h["health"], h["up"],
                              _r(h.get("cpu")), _r(h.get("memory")), _r(h.get("disk")), _r(h.get("load1")),
                              _r(h.get("cores"), 0), _r(h.get("rx"), 0), _r(h.get("tx"), 0), _r(h.get("uptime"), 0)]
                             for h in rows])

    page = paginate(request, rows)
    for i, h in enumerate(page):
        vals = sparks.get(h["instance"]) or []
        h["spark"] = {"values": vals, "color": "#dc2626" if h["health"] in ("critical", "down") else
                      "#f59e0b" if h["health"] == "warning" else "#1565f0"} if len(vals) >= 2 else None
        h["spark_id"] = f"spark-{i}"
        h["rx_text"], h["tx_text"], h["uptime_text"] = human_rate(h.get("rx")), human_rate(h.get("tx")), human_duration(h.get("uptime"))
    c = summary["counts"]
    ctx.update({
        "summary": summary, "page": page, "jobs": jobs, "health_choices": HEALTH_CHOICES,
        "query": query_without_page(request, "refresh"), "filtered": bool(q or health or job),
        "donut": {"segments": [
            {"label": "Healthy", "value": c["healthy"], "color": "#16a34a"},
            {"label": "Warning", "value": c["warning"], "color": "#f59e0b"},
            {"label": "Critical", "value": c["critical"], "color": "#dc2626"},
            {"label": "Down", "value": c["down"], "color": "#7f1d1d"},
            {"label": "No data", "value": c["unknown"], "color": "#cbd5e1"}],
            "center": {"value": str(summary["total"]), "label": "Hosts"}},
        "top_cpu": svc.top(hosts, "cpu"), "top_memory": svc.top(hosts, "memory"), "top_disk": svc.top(hosts, "disk"),
        "thresholds": svc.thresholds(),
    })
    return render(request, "telemetry/infrastructure.html", ctx)


def _r(v, digits=2):
    return "" if not finite(v) else round(v, digits)


@require("view")
def host_detail(request, instance):
    ctx = {**prom_context(), **perms(request), "instance": instance, "error": "", "host": None}
    range_key = request.GET.get("range", "1h")
    if range_key not in svc.RANGES:
        range_key = "1h"
    ci = svc.cmdb_map([instance]).get(instance)
    site = (getattr(ci, "site", "") or "") if ci is not None else ""
    if not _site_ok(request.user, site):
        raise Http404("No such host")
    status = 200
    if ctx["prom_configured"]:
        try:
            ctx["host"] = svc.fetch_host(instance, range_key, use_cache=request.GET.get("refresh") != "1")
            if ctx["host"] is None:
                status = 404
        except prometheus.PrometheusError as e:
            ctx["error"] = str(e)
    # alerts carry their own site (label or CMDB): a host without a CI is global, its alerts may not be
    alerts = (scope_by_site(Alert.objects.for_tenant(), request.user, field="site")
              .filter(instance=instance).order_by("status", "-last_received_at")[:10])
    ctx.update({"ci": ci, "ci_url": svc.ci_url(ci), "site": site, "range_key": range_key,
                "ranges": [(k, v[0]) for k, v in svc.RANGES.items()], "alerts": alerts,
                "explore_q": svc.range_queries(instance)["cpu"]})
    return render(request, "telemetry/host_detail.html", ctx, status=status)
