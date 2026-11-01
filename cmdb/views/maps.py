"""Topology graph and the service heatmap."""
from django.core.paginator import Paginator
from django.shortcuts import render
from django.urls import reverse

from core import prometheus
from core.access import require

from .. import heatmap as hm
from .. import services, topology
from ..models import CIType
from .common import perms, query_without_page

SEVERITY = services.SEVERITY


@require("view")
def topology_view(request):
    show_retired = request.GET.get("retired") == "1"
    qs = services.ci_queryset(request.user)
    if not show_retired:
        qs = qs.exclude(status="retired")
    env = request.GET.get("env", "")
    if env:
        qs = qs.filter(environment=env)
    cis = list(qs.only("pk", "name", "ci_type", "status", "business_domain", "site", "environment"))
    ci_map = {c.pk: c for c in cis}
    edges = [e for e in services.edges_for() if e[1] in ci_map and e[2] in ci_map]
    domain = request.GET.get("domain", "").strip()
    root_id = request.GET.get("root", "")
    root = ci_map.get(int(root_id)) if root_id.isdigit() else None
    note = ""
    if root is not None:
        keep = topology.neighbourhood(root.pk, edges)
        scope = f"Everything {root.name} depends on and everything that depends on it"
    elif domain:
        keep = topology.domain_scope(domain, cis, edges)
        scope = f"Business domain {domain} and the infrastructure it relies on"
    else:
        keep = set(ci_map)
        scope = "All configuration items"
    if len(keep) > topology.MAX_NODES:
        # keep the most connected items so the drawing stays useful
        degree = {}
        for _pk, s, t, _rt in edges:
            degree[s] = degree.get(s, 0) + 1
            degree[t] = degree.get(t, 0) + 1
        ranked = sorted(keep, key=lambda pk: (-degree.get(pk, 0), ci_map[pk].name.lower()))
        keep = set(ranked[:topology.MAX_NODES])
        note = (f"Showing the {topology.MAX_NODES} most connected of {len(ranked)} items. "
                "Filter by business domain or root item to see the rest.")
    hide_isolated = request.GET.get("isolated") != "1" and root is None
    sub_edges = [e for e in edges if e[1] in keep and e[2] in keep]
    if hide_isolated and not domain:
        connected = {e[1] for e in sub_edges} | {e[2] for e in sub_edges}
        isolated = len(keep - connected)
        keep = connected if connected else keep
    else:
        isolated = 0
    nodes = [ci_map[pk] for pk in keep]
    health = services.link_health(nodes)
    graph = topology.layout(nodes, sub_edges, health, root_id=root.pk if root else None)
    counts = {s: sum(1 for n in graph["nodes"] if n["state"] == s) for s in ("healthy", "warning", "critical", "unknown")}
    return render(request, "cmdb/topology.html", {
        "graph": graph, "domain": domain, "root": root, "scope": scope, "note": note, "isolated": isolated,
        "domains": services.domain_names(request.user), "roots": sorted(cis, key=lambda c: c.name.lower()),
        "env": env, "envs": [("prod", "Production"), ("uat", "UAT"), ("dr", "DR"), ("dev", "Development")],
        "show_retired": show_retired, "counts": counts, "edge_count": len(graph["edges"]),
        "query": query_without_page(request), **perms(request)})


def _top_services(rows, n=5):
    return sorted(rows, key=lambda r: (-SEVERITY.get(r["health"], 0), r["metrics"]["availability"] if
                                       r["metrics"]["availability"] is not None else 101, r["name"].lower()))[:n]


@require("view")
def heatmap_view(request):
    g = request.GET
    domain, service, host = g.get("domain", "").strip(), g.get("service", "").strip(), g.get("host", "").strip()
    window = g.get("window", hm.DEFAULT_WINDOW)
    d = hm.build(request.user, domain=domain, service=service, host=host, window=window)

    domains = d["domains"]
    sel = None
    if domain:
        sel = next((x for x in domains if x["name"].lower() == domain.lower()), None)
    if sel is None and service:
        sel = next((x for x in domains if any(r["name"] == service for r in x["service_rows"])), None)
    if sel is None and domains:
        sel = sorted(domains, key=lambda x: (-SEVERITY.get(x["health"], 0), -x["services"], x["name"].lower()))[0]

    tab = g.get("tab", "overview")
    if tab not in ("overview", "services", "incidents"):
        tab = "overview"
    details = None
    if sel is not None:
        member_cis = [r["ci"] for r in sel["service_rows"]]
        names = [sel["name"]] + [c.name for c in member_cis]
        incidents = services.recent_incidents(names, limit=8 if tab == "incidents" else 5,
                                              fingerprints=services.ci_fingerprints(member_cis))
        health = services.link_health(d["ci_map"].values())
        health.update(hm.health_from_rows(domains))
        rows = sorted(sel["service_rows"], key=lambda r: r["name"].lower()) if tab == "services" else _top_services(sel["service_rows"])
        details = {
            "dom": sel, "tab": tab, "rows": rows, "incidents": incidents,
            "chain": hm.domain_chain(sel, d["edges"], d["ci_map"], health),
        }

    dpage = Paginator(domains, 8).get_page(g.get("dpage"))
    kpis = [
        {"label": "Total Domains", "value": len(domains), "tile": "bg-info", "icon": "bar", "filled": False},
        {"label": "Healthy", "value": d["counts"]["healthy"], "tile": "bg-ok", "icon": "check-circle", "filled": True},
        {"label": "Warning", "value": d["counts"]["warning"], "tile": "bg-warn", "icon": "shield-alert", "filled": False},
        {"label": "Critical", "value": d["counts"]["critical"], "tile": "bg-crit", "icon": "x-circle", "filled": True},
        {"label": "Unknown", "value": d["counts"]["unknown"], "tile": "bg-mute", "icon": "help", "filled": True},
    ]
    keep = query_without_page(request)
    for k in ("tab", "dpage"):
        keep.pop(k, None)
    links = {
        "logs": services._safe_reverse("observe:logs"), "metrics": services._safe_reverse("telemetry:explorer"),
        "add_domain": reverse("cmdb:item_create") + "?type=" + CIType.BUSINESS_DOMAIN + "&next=" + reverse("cmdb:heatmap"),
    }
    return render(request, "cmdb/heatmap.html", {
        "d": d, "sel": sel, "details": details, "dpage": dpage, "kpis": kpis, "keep": keep,
        "f": {"domain": domain, "service": service, "host": host}, "links": links,
        "prom_configured": prometheus.configured(), **perms(request)})
