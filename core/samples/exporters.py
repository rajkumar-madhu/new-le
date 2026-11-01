"""Illustrative data for the exporters page (shown with a "Sample data" label)."""
import random
from datetime import timedelta

from django.core.paginator import Paginator
from django.utils import timezone

HEALTH = ["ok", "warn", "crit"]


def _rng(name):
    return random.Random(name)


# category -> (icon, colour); shared by the category strip and the table's Category column
CATEGORY_STYLE = {
    "Network": ("network", "#2563eb"), "Firewalls": ("brick", "#ef4444"), "Servers": ("server", "#7c3aed"),
    "Virtualization": ("layers", "#9333ea"), "Storage": ("hdd", "#f59e0b"), "Databases": ("database", "#2563eb"),
    "Applications": ("app", "#c026d3"), "Kubernetes": ("hexagon", "#0891b2"), "Wireless": ("wifi", "#16a34a"),
    "Security": ("shield", "#f97316"), "Custom": ("settings", "#64748b"),
}
CATEGORIES = list(CATEGORY_STYLE)
# how many exporters each category holds (sums to 87)
CATEGORY_SIZE = {"Network": 10, "Firewalls": 9, "Servers": 9, "Virtualization": 8, "Storage": 7, "Databases": 8,
                 "Applications": 10, "Kubernetes": 8, "Wireless": 7, "Security": 7, "Custom": 4}
SITES = ["Mumbai DC", "Pune DR", "Bengaluru HQ"]
STATUSES = [("active", "Active"), ("inactive", "Inactive"), ("error", "Error"), ("not_configured", "Not Configured")]

# the first ten rows, as listed on the design
EXPORTERS = [
    ("snmp-switch-01", "SNMP", "Network", "10.10.1.10", 12450, "2 min ago"),
    ("fortinet-fw-01", "HTTP API", "Firewalls", "192.168.1.1", 8230, "1 min ago"),
    ("node-exporter-01", "Node Exporter", "Servers", "srv-app-01", 45621, "2 min ago"),
    ("windows-exporter", "Windows", "Servers", "win-srv-01", 23112, "3 min ago"),
    ("vmware-exporter", "vSphere", "Virtualization", "vcenter01", 15890, "2 min ago"),
    ("mysql-exporter", "MySQL", "Databases", "db-prod-01", 34556, "1 min ago"),
    ("blackbox-exporter", "HTTP/TCP", "Applications", "https://wecrew.in", 22345, "30 sec ago"),
    ("kube-state-metrics", "Kubernetes", "Kubernetes", "k8s-cluster-01", 28991, "1 min ago"),
    ("netflow-exporter", "NetFlow", "Network", "192.168.10.1", 11234, "2 min ago"),
    ("syslog-exporter", "Syslog", "Security", "syslog-server", 67890, "30 sec ago"),
]
# per-category (name stem, type, target stem) used to fill the rest of the inventory
TEMPLATES = {
    "Network": [("snmp-switch", "SNMP", "10.10.1."), ("snmp-router", "SNMP", "10.10.0."), ("netflow-edge", "NetFlow", "192.168.10.")],
    "Firewalls": [("fortinet-fw", "HTTP API", "192.168.1."), ("paloalto-fw", "HTTP API", "192.168.2.")],
    "Servers": [("node-exporter", "Node Exporter", "srv-app-"), ("win-exporter", "Windows", "win-srv-"), ("ipmi-exporter", "IPMI", "idrac-mum-")],
    "Virtualization": [("esxi-exporter", "vSphere", "esxi-"), ("pve-exporter", "Proxmox", "pve-")],
    "Storage": [("netapp-harvest", "ONTAP API", "netapp-"), ("ceph-exporter", "Ceph", "ceph-mon-")],
    "Databases": [("pg-exporter", "PostgreSQL", "pg-ledger-"), ("redis-exporter", "Redis", "redis-bod-"), ("mysql-exporter", "MySQL", "db-prod-")],
    "Applications": [("http-probe", "HTTP/TCP", "app"), ("nginx-exporter", "Nginx", "web-"), ("jmx-exporter", "JMX", "jvm-")],
    "Kubernetes": [("kube-state", "Kubernetes", "k8s-cluster-"), ("cadvisor", "cAdvisor", "k8s-node-")],
    "Wireless": [("aruba-exporter", "SNMP", "aruba-ctrl-"), ("unifi-exporter", "UniFi API", "unifi-")],
    "Security": [("syslog-relay", "Syslog", "syslog-"), ("wazuh-api", "Wazuh API", "wazuh-")],
    "Custom": [("script-exporter", "Script", "job-"), ("pushgateway", "Pushgateway", "push-")],
}
LOG_LINES = [
    ("snmp-switch-01", "INFO", "Interface Gi1/0/1 status up"), ("fortinet-fw-01", "WARN", "High session count: 9800"),
    ("node-exporter-01", "INFO", "CPU usage: 45%"), ("mysql-exporter", "ERROR", "Slow query detected (2.3s)"),
    ("blackbox-exporter", "INFO", "HTTPS check success (200)"), ("vmware-exporter", "INFO", "Datastore usage: 78%"),
    ("syslog-exporter", "WARN", "Failed login attempt from 10.1.1.5"), ("windows-exporter", "INFO", "Memory usage: 62%"),
    ("kube-state-metrics", "INFO", "Pod restart detected: api-7d9c8"), ("netflow-exporter", "INFO", "High traffic from 192.168.20.10"),
]
EVENTS = [
    ("Critical", "High CPU on srv-app-01"), ("Warning", "Firewall session threshold exceeded"), ("Info", "SSL certificate expiring (7 days)"),
    ("Warning", "VM datastore usage high"), ("Info", "Pod restart detected: api-7d9c8"), ("Critical", "Switch port down: Gi1/0/24"),
    ("Warning", "Failed login attempt detected"), ("Info", "HTTPS check failed: customer.in"),
]
SEVERITY = {"Critical": ("t-crit", "x-circle"), "Warning": ("t-warn", "alert"), "Info": ("t-info", "info")}
# rows (by position after the first ten) that are not active: 6 inactive, 4 error, 5 not configured -> 72 active of 87
NOT_ACTIVE = {12: "error", 19: "inactive", 23: "not_configured", 28: "inactive", 34: "error", 41: "not_configured",
              46: "inactive", 52: "error", 57: "inactive", 61: "not_configured", 66: "inactive", 70: "error",
              74: "not_configured", 79: "inactive", 84: "not_configured"}
PER_PAGE = (10, 20, 50)


def _inventory(r):
    rows = []
    for name, typ, cat, target, logs, seen in EXPORTERS:
        rows.append({"name": name, "type": typ, "category": cat, "target": target, "logs": logs, "last_seen": seen})
    used = {}
    for row in rows:
        used[row["category"]] = used.get(row["category"], 0) + 1
    extra = []
    for cat in CATEGORIES:
        for k in range(CATEGORY_SIZE[cat] - used.get(cat, 0)):
            stem, typ, tgt = TEMPLATES[cat][k % len(TEMPLATES[cat])]
            n = k // len(TEMPLATES[cat]) + 2
            target = f"{tgt}{r.randint(2, 250)}" if tgt.endswith(".") else (f"{tgt}{n}.wecrew.in" if tgt == "app" else f"{tgt}{n:02d}")
            extra.append({"name": f"{stem}-{n:02d}", "type": typ, "category": cat, "target": target,
                          "logs": r.randint(400, 11000), "last_seen": r.choice(["30 sec ago", "1 min ago", "2 min ago", "3 min ago"])})
    r.shuffle(extra)
    rows += extra
    for i, row in enumerate(rows):
        status = NOT_ACTIVE.get(i, "active")
        row["status"] = status
        row["status_label"] = dict(STATUSES)[status]
        if status != "active":
            row["last_seen"] = "never" if status == "not_configured" else f"{r.randint(2, 9)} h ago"
            row["logs"] = 0 if status == "not_configured" else row["logs"] // 20
        row["no"] = i + 1
        row["site"] = SITES[i % len(SITES)]
        row["cat_icon"], row["cat_color"] = CATEGORY_STYLE[row["category"]]
    return rows


def _pct(n, total):
    return round(100 * n / total, 1) if total else 0


def exporters(request=None):
    params = request.GET if request is not None else {}
    r = _rng("exporters")
    now = timezone.localtime()
    rows = _inventory(r)
    total = len(rows)

    # filters (search box, category strip / select, status and site selects)
    q = (params.get("q") or "").strip()
    category = params.get("category") or ""
    status = params.get("status") or ""
    site = params.get("site") or ""
    shown = [x for x in rows
             if (not q or any(q.lower() in str(x[k]).lower() for k in ("name", "type", "target")))
             and (not category or x["category"] == category)
             and (not status or x["status"] == status)
             and (not site or x["site"] == site)]
    try:
        per = int(params.get("per") or 10)
    except ValueError:
        per = 10
    per = per if per in PER_PAGE else 10
    page = Paginator(shown, per).get_page(params.get("page"))
    query = params.copy() if request is not None else None
    if query is not None:
        query.pop("page", None)
    strip_query = params.copy() if request is not None else None
    if strip_query is not None:
        for k in ("page", "category"):
            strip_query.pop(k, None)

    logs = [{"time": (now - timedelta(seconds=2 * i + r.randint(0, 1))).strftime("%H:%M:%S"), "exporter": e, "level": lvl, "msg": m}
            for i, (e, lvl, m) in enumerate(LOG_LINES)]
    hours = [f"{h:02d}:00" for h in range(24)]
    trend = {"labels": hours, "unit": "", "yMax": 80000, "yTicks": 4, "xLabelEvery": 4, "series": [
        {"name": "Info", "color": "#1565f0", "values": [r.randint(18, 42) * 1000 for _ in hours]},
        {"name": "Warn", "color": "#f59e0b", "values": [r.randint(3, 10) * 1000 for _ in hours]},
        {"name": "Error", "color": "#dc2626", "values": [r.randint(1, 5) * 1000 for _ in hours]}]}
    cats = [{"name": c, "count": sum(1 for x in rows if x["category"] == c), "icon": CATEGORY_STYLE[c][0],
             "color": CATEGORY_STYLE[c][1]} for c in CATEGORIES]
    top = sorted(rows, key=lambda x: -x["logs"])[:8]
    events = []
    for i, (s, m) in enumerate(EVENTS):
        tone, ic = SEVERITY[s]
        events.append({"time": (now - timedelta(minutes=2 * i + 1)).strftime("%H:%M"), "sev": s, "tone": tone, "icon": ic, "msg": m})
    health = {k: sum(x["status"] == k for x in rows) for k, _ in STATUSES}
    legend = [{"label": "Active", "n": health["active"], "color": "#16a34a"},
              {"label": "Inactive", "n": health["inactive"], "color": "#94a3b8"},
              {"label": "Error", "n": health["error"], "color": "#ef4444"},
              {"label": "Not Configured", "n": health["not_configured"], "color": "#f59e0b"}]
    for seg in legend:
        seg["pct"] = _pct(seg["n"], total)
    return {"rows": page.object_list, "all_rows": rows, "page": page, "query": query, "strip_query": strip_query,
            "filters": {"q": q, "category": category, "status": status, "site": site},
            "categories": CATEGORIES, "statuses": STATUSES, "sites": SITES,
            "logs": logs, "trend": trend, "cats": cats, "counts": {c["name"]: c["count"] for c in cats},
            "top": top, "top_max": top[0]["logs"], "events": events, "health": health, "legend": legend, "total": total,
            "pct": {k: _pct(v, total) for k, v in health.items()},
            "donut": {"segments": [{"label": s["label"], "value": s["n"], "color": s["color"]} for s in legend],
                      "center": {"value": str(total), "label": "Exporters"}, "thickness": 22}}
