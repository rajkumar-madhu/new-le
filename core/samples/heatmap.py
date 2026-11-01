"""Illustrative data for the heatmap page (shown with a "Sample data" label)."""
import random

HEALTH = ["ok", "warn", "crit"]


def _rng(name):
    return random.Random(name)


HEAT_COLUMNS = ["Availability", "Response", "Errors", "Latency", "CPU", "Memory", "Disk", "Network"]
HEAT_GROUPS = {
    "Trading": ["OMS", "Trade Adapter", "Risk Engine", "Market Data", "Order Gateway"],
    "Infrastructure": ["Kubernetes", "Node Exporter", "SNMP Devices", "Blackbox Probes", "Load Balancers"],
    "Applications": ["LinkedEye", "ITSM", "Keycloak", "Jenkins", "Harbor", "SonarQube"],
    "Databases": ["PostgreSQL", "Redis", "RabbitMQ", "MongoDB"],
    "External Services": ["Exchange APIs", "Broker API (MCX)"],
}
# Cell pattern per service (Availability, Response, Errors, Latency, CPU, Memory, Disk, Network):
# g=healthy, w=warning, r=critical. Group rows use their own pattern (as in the design).
PATTERN = {
    "Trading": "gggggggr", "OMS": "ggggwgwr", "Trade Adapter": "ggrggggg", "Risk Engine": "gggggggg",
    "Market Data": "gwgggggg", "Order Gateway": "ggggwggg",
    "Infrastructure": "gggggggg", "Kubernetes": "wgggwggg", "Node Exporter": "gggggggw", "SNMP Devices": "ggrggggg",
    "Blackbox Probes": "gwgggggg", "Load Balancers": "gggggggg",
    "Applications": "gggggggg", "LinkedEye": "ggggwggg", "ITSM": "gwgwgggg", "Keycloak": "gggwgggg",
    "Jenkins": "grgggggg", "Harbor": "gggggggg", "SonarQube": "gggggggg",
    "Databases": "gggggggg", "PostgreSQL": "gggwggwg", "Redis": "ggggwggg", "RabbitMQ": "grgggggr", "MongoDB": "gggggggg",
    "External Services": "gggggggg", "Exchange APIs": "gggwgggg", "Broker API (MCX)": "rggggggr",
}
CODE = {"g": "ok", "w": "warn", "r": "crit"}

HOSTS = ["prod-oms-01", "prod-oms-02", "prod-k8s-node-01", "prod-k8s-node-02", "prod-db-01", "prod-redis-01", "dr-oms-01"]
RANGES = ["Last 15 minutes", "Last 1 hour", "Last 6 hours", "Last 24 hours", "Last 7 days"]

# (name, description, services, health, availability %, error rate %, p95 ms, icon, icon tone)
DOMAINS = [
    ("Trading", "Trading and order management systems", 8, "critical", 99.21, 2.4, 620, "radar", "t-crit"),
    ("Infrastructure", "Core infrastructure and platform", 6, "warning", 99.88, 0.6, 180, "network", "t-info"),
    ("Applications", "Business and internal applications", 7, "healthy", 99.94, 0.3, 120, "layers", "t-info"),
    ("Databases", "Database and cache services", 4, "healthy", 99.96, 0.2, 85, "database", "t-info"),
    ("External Services", "Third party and exchange services", 3, "warning", 99.73, 1.1, 340, "globe", "hm-purple"),
    ("Security", "Identity and security services", 3, "healthy", 99.99, 0.1, 45, "shield", "hm-purple"),
]
KEYS = ("name", "desc", "services", "health", "avail", "err", "p95", "icon", "tone")


def heatmap():
    r = _rng("heatmap")

    def cells(name):
        pat = PATTERN.get(name)
        if pat:
            return [CODE[c] for c in pat]
        return [r.choices(HEALTH, weights=[86, 9, 5])[0] for _ in HEAT_COLUMNS]

    rows = []
    for group, services in HEAT_GROUPS.items():
        svc_rows = [{"name": s, "cells": cells(s)} for s in services]
        rows.append({"group": group, "cells": cells(group), "services": svc_rows})

    domains = [dict(zip(KEYS, t)) for t in DOMAINS]
    for dm in domains:
        dm["hot"] = dm["health"] in ("critical", "warning") and dm["err"] > 1
    counts = {h: sum(1 for dm in domains if dm["health"] == h) for h in ("healthy", "warning", "critical", "unknown")}
    kpis = [
        {"label": "Total Domains", "value": len(domains), "tile": "bg-info", "icon": "bar", "filled": False},
        {"label": "Healthy", "value": counts["healthy"], "tile": "bg-ok", "icon": "check-circle", "filled": True},
        {"label": "Warning", "value": counts["warning"], "tile": "bg-warn", "icon": "shield-alert", "filled": False},
        {"label": "Critical", "value": counts["critical"], "tile": "bg-crit", "icon": "x-circle", "filled": True},
        {"label": "Unknown", "value": counts["unknown"], "tile": "bg-mute", "icon": "info", "filled": True},
    ]

    top_services = [
        {"name": n, "health": h, "avail": a, "err": e, "p95": p}
        for n, h, a, e, p in [("OMS", "critical", 99.02, 3.1, 820), ("Trade Adapter", "warning", 99.61, 1.2, 420),
                              ("Risk Engine", "healthy", 99.98, 0.1, 110), ("Market Data", "healthy", 99.95, 0.2, 95),
                              ("Order Gateway", "warning", 99.71, 1.0, 310)]
    ]
    incidents = [
        {"id": i, "prio": p, "title": t, "ago": ago}
        for i, p, t, ago in [("INC000123", "P1", "OMS processing delay", "87m"),
                             ("INC000122", "P2", "Adapter connection errors", "2h"),
                             ("INC000121", "P2", "High order rejection rate", "3h"),
                             ("INC000118", "P3", "Market data feed latency", "5h"),
                             ("INC000117", "P3", "Risk engine timeout", "8h")]
    ]
    chain = [
        {"name": "Exchange", "icon": "globe", "tone": "t-info"},
        {"name": "Market Data", "icon": "bar", "tone": "hm-orange"},
        {"name": "OMS", "icon": "server", "tone": "t-crit", "hot": True},
        {"name": "Risk Engine", "icon": "network", "tone": "t-ok"},
        {"name": "Database", "icon": "database", "tone": "t-info"},
    ]
    return {
        "columns": HEAT_COLUMNS, "rows": rows, "groups": list(HEAT_GROUPS),
        "services": [s for svcs in HEAT_GROUPS.values() for s in svcs], "hosts": HOSTS, "ranges": RANGES,
        "domains": domains, "domain_kpis": kpis, "selected": domains[0],
        "top_services": top_services, "incidents": incidents, "open_incidents": 3, "chain": chain,
    }
