"""Heatmap data: business domains -> services, with health per metric.

Probe columns (Availability, Response, Errors, Latency) come from the service's linked URL checks
(UrlResult) and domains (DomainCheck) inside the selected window. Host columns (CPU, Memory, Disk,
Network) come from Prometheus node_exporter when settings.PROMETHEUS_URL is set and the service (or
the host it runs on) has a `prometheus_instance`. Anything without data is "unknown" (grey).
"""
import math
import re
from collections import defaultdict
from datetime import timedelta

from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

from core import prometheus

from . import services
from .models import HOST_TYPES, SERVICE_TYPES, CIType, ConfigurationItem, RelType

WINDOWS = {"1h": ("Last 1 hour", 3600), "6h": ("Last 6 hours", 6 * 3600),
           "24h": ("Last 24 hours", 24 * 3600), "7d": ("Last 7 days", 7 * 86400)}
DEFAULT_WINDOW = "1h"

COLUMNS = [
    ("availability", "Availability"), ("response", "Response"), ("errors", "Errors"), ("latency", "Latency"),
    ("cpu", "CPU"), ("memory", "Memory"), ("disk", "Disk"), ("network", "Network"),
]
PROBE_COLS = ["availability", "response", "errors", "latency"]
HOST_COLS = ["cpu", "memory", "disk", "network"]

# (healthy-if, warning-if) limits. Availability is "higher is better"; the rest "lower is better".
# Response/latency limits are multiples of the linked checks' degraded threshold (default 1000 ms).
DEFAULT_THRESHOLDS = {
    "availability": (99.5, 97.0),   # %
    "errors": (1.0, 5.0),           # % of samples
    "response": (1.0, 2.0),         # x degraded_ms (average)
    "latency": (1.5, 3.0),          # x degraded_ms (p95)
    "cpu": (70.0, 85.0),            # % busy
    "memory": (80.0, 90.0),         # % used
    "disk": (80.0, 90.0),           # % used, fullest filesystem
    "network": (0.1, 1.0),          # errors + drops per second
}

PROMQL = {
    "cpu": '100 * (1 - avg by (instance) (rate(node_cpu_seconds_total{{mode="idle",instance=~"{re}"}}[5m])))',
    "memory": '100 * (1 - (node_memory_MemAvailable_bytes{{instance=~"{re}"}} / node_memory_MemTotal_bytes{{instance=~"{re}"}}))',
    "disk": ('100 * max by (instance) (1 - (node_filesystem_avail_bytes{{instance=~"{re}",fstype!~"tmpfs|overlay|squashfs|ramfs"}}'
             ' / node_filesystem_size_bytes{{instance=~"{re}",fstype!~"tmpfs|overlay|squashfs|ramfs"}}))'),
    "network": ('sum by (instance) (rate(node_network_receive_errs_total{{instance=~"{re}"}}[5m])'
                ' + rate(node_network_transmit_errs_total{{instance=~"{re}"}}[5m])'
                ' + rate(node_network_receive_drop_total{{instance=~"{re}"}}[5m])'
                ' + rate(node_network_transmit_drop_total{{instance=~"{re}"}}[5m]))'),
}
UNITS = {"cpu": "%", "memory": "%", "disk": "%", "network": "/s"}

STATE_CLASS = services.STATE_CLASS


def thresholds():
    t = dict(DEFAULT_THRESHOLDS)
    t.update(getattr(settings, "CMDB_HEATMAP_THRESHOLDS", {}) or {})
    return t


def grade(col, value, base_ms=1000.0):
    """Health state for a metric value (None -> unknown)."""
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return "unknown"
    ok, warn = thresholds()[col]
    if col == "availability":
        return "healthy" if value >= ok else "warning" if value >= warn else "critical"
    if col in ("response", "latency"):
        ok, warn = ok * base_ms, warn * base_ms
    return "healthy" if value <= ok else "warning" if value <= warn else "critical"


def p95(values):
    if not values:
        return None
    v = sorted(values)
    k = max(0, math.ceil(0.95 * len(v)) - 1)
    return v[k]


def promql_regex(instances):
    """Anchored RE2 alternation of literal instance names, escaped for a PromQL double-quoted string."""
    alt = "|".join(re.sub(r"([.^$*+?()\[\]{}|\\])", r"\\\1", i) for i in sorted(instances))
    return alt.replace("\\", "\\\\").replace('"', '\\"')


# ----------------------------------------------------------------------------- samples
class Samples:
    """Probe samples pooled for one service (or a whole domain)."""

    __slots__ = ("total", "up", "errors", "ms", "base_ms")

    def __init__(self):
        self.total = self.up = self.errors = 0
        self.ms = []
        self.base_ms = None

    def add(self, available, error, ms):
        self.total += 1
        self.up += 1 if available else 0
        self.errors += 1 if error else 0
        if ms is not None and available:
            self.ms.append(ms)

    def merge(self, other):
        self.total += other.total
        self.up += other.up
        self.errors += other.errors
        self.ms.extend(other.ms)
        if other.base_ms is not None:
            self.base_ms = other.base_ms if self.base_ms is None else min(self.base_ms, other.base_ms)

    def metrics(self):
        if not self.total:
            return {c: None for c in PROBE_COLS}
        return {
            "availability": 100.0 * self.up / self.total,
            "errors": 100.0 * self.errors / self.total,
            "response": (sum(self.ms) / len(self.ms)) if self.ms else None,
            "latency": p95(self.ms),
        }


def probe_samples(check_ids, domain_ids, since):
    """{("url", id) | ("domain", id): Samples} from stored results since `since`."""
    from domainmonitor.models import DomainCheck
    from urlchecker.models import UrlResult
    out = defaultdict(Samples)
    if check_ids:
        rows = UrlResult.objects.filter(url_check_id__in=check_ids, checked_at__gte=since).values_list(
            "url_check_id", "status", "http_status", "response_ms")
        for cid, status, http, ms in rows.iterator(chunk_size=5000):
            available = status != "down"
            # transport/server errors: no HTTP answer at all, or 5xx. A content mismatch only hurts availability.
            error = (status == "down" and http is None) or (http is not None and http >= 500)
            out[("url", cid)].add(available, error, ms)
    if domain_ids:
        rows = DomainCheck.objects.filter(domain_id__in=domain_ids, checked_at__gte=since).values_list(
            "domain_id", "up", "http_status", "response_ms")
        for did, up, http, ms in rows.iterator(chunk_size=5000):
            out[("domain", did)].add(up, (not up) or (http is not None and http >= 500), ms)
    return out


# ----------------------------------------------------------------------------- prometheus
def host_metrics(instances):
    """({instance: {cpu, memory, disk, network}}, error message or "") using node_exporter queries."""
    if not instances or not prometheus.configured():
        return {}, ""
    key = "cmdb:hm:" + str(abs(hash(tuple(sorted(instances)))))
    hit = cache.get(key)
    if hit is not None:
        return hit, ""
    rx = promql_regex(instances)
    values = defaultdict(dict)
    try:
        for col, tpl in PROMQL.items():
            for r in prometheus.query(tpl.format(re=rx)):
                inst = r["metric"].get("instance")
                if inst in instances and r["value"] is not None and not math.isnan(r["value"]):
                    values[inst][col] = r["value"]
    except prometheus.PrometheusError as e:
        return {}, str(e)
    values = dict(values)
    cache.set(key, values, 30)
    return values, ""


def instances_for(services_, edges, ci_map):
    """{service pk: [instance labels]} from the service itself or the hosts it runs on (up to 3 hops)."""
    down = defaultdict(list)
    for _pk, s, t, rt in edges:
        if rt in (RelType.RUNS_ON, RelType.HOSTED_ON, RelType.DEPENDS_ON):
            down[s].append((t, rt))
    out = {}
    for svc in services_:
        if svc.prometheus_instance:
            out[svc.pk] = [svc.prometheus_instance]
            continue
        found, frontier, seen = [], [svc.pk], {svc.pk}
        for _hop in range(3):
            nxt = []
            for cur in frontier:
                for t, rt in down.get(cur, ()):
                    c = ci_map.get(t)
                    if t in seen or c is None:
                        continue
                    seen.add(t)
                    # follow runs_on/hosted_on anywhere; depends_on only towards host-type CIs
                    if rt == RelType.DEPENDS_ON and c.ci_type not in HOST_TYPES:
                        continue
                    if c.prometheus_instance:
                        found.append(c.prometheus_instance)
                    nxt.append(t)
            if found:
                break
            frontier = nxt
        out[svc.pk] = found
    return out


def hosts_for(services_, edges, ci_map):
    """{service pk: set(host CI pks)} — host-type CIs reachable through runs_on/hosted_on (3 hops)."""
    down = defaultdict(list)
    for _pk, s, t, rt in edges:
        if rt in (RelType.RUNS_ON, RelType.HOSTED_ON):
            down[s].append(t)
    out = {}
    for svc in services_:
        seen, frontier = set(), [svc.pk]
        for _hop in range(3):
            nxt = []
            for cur in frontier:
                for t in down.get(cur, ()):
                    if t not in seen and t in ci_map:
                        seen.add(t)
                        nxt.append(t)
            frontier = nxt
        out[svc.pk] = {h for h in seen if ci_map[h].ci_type in HOST_TYPES}
    return out


# ----------------------------------------------------------------------------- formatting
def _fmt(col, v):
    if v is None:
        return "no data"
    if col in ("availability", "errors"):
        return f"{v:.2f}%"
    if col in ("response", "latency"):
        return f"{v:,.0f} ms"
    if col == "network":
        return f"{v:.2f} err/s"
    return f"{v:.1f}%"


def _cell(col, value, base_ms, note=""):
    state = grade(col, value, base_ms or 1000.0)
    label = dict(COLUMNS)[col]
    title = f"{label}: {_fmt(col, value)}"
    if note and value is None:
        title += f" ({note})"
    return {"col": col, "state": state, "cls": STATE_CLASS[state], "value": value, "text": _fmt(col, value), "title": title}


# ----------------------------------------------------------------------------- main entry
def build(user, domain="", service="", host="", window=DEFAULT_WINDOW):
    window = window if window in WINDOWS else DEFAULT_WINDOW
    since = timezone.now() - timedelta(seconds=WINDOWS[window][1])
    cis = list(services.ci_queryset(user).exclude(status="retired").prefetch_related("url_checks", "domains"))
    ci_map = {c.pk: c for c in cis}
    edges = [e for e in services.edges_for() if e[1] in ci_map and e[2] in ci_map]
    domain_names = services.domain_names(user)

    # group services by domain
    groups = []
    assigned = set()
    for name in domain_names:
        dom_ci, members = services.domain_members(name, cis=cis, edges=edges, types=SERVICE_TYPES)
        assigned.update(m.pk for m in members)
        groups.append({"name": name, "ci": dom_ci, "services": sorted(members, key=lambda c: c.name.lower())})
    loose = [c for c in cis if c.ci_type in SERVICE_TYPES and c.pk not in assigned]
    if loose:
        groups.append({"name": "Unassigned", "ci": None, "services": sorted(loose, key=lambda c: c.name.lower()),
                       "unassigned": True})

    all_services = {s.pk: s for g in groups for s in g["services"]}
    host_map = hosts_for(all_services.values(), edges, ci_map)
    host_choices = sorted({ci_map[h] for hs in host_map.values() for h in hs}, key=lambda c: c.name.lower())

    # filters
    try:
        host_id = int(host) if host else None
    except ValueError:
        host_id = None
    domain_key = domain.lower()

    def keep(g, s):
        if domain and g["name"].lower() != domain_key:
            return False
        if service and s.name != service:
            return False
        if host_id and host_id not in host_map.get(s.pk, ()):
            return False
        return True

    # probe data
    check_ids = {c.pk for s in all_services.values() for c in s.url_checks.all()}
    domain_ids = {d.pk for s in all_services.values() for d in s.domains.all()}
    samples = probe_samples(check_ids, domain_ids, since)

    # prometheus data
    prom_on = prometheus.configured()
    inst_map = instances_for(all_services.values(), edges, ci_map)
    wanted = {i for v in inst_map.values() for i in v}
    host_values, prom_error = host_metrics(wanted) if prom_on else ({}, "")
    prom_note = ("Prometheus not connected" if not prom_on else
                 "Prometheus error" if prom_error else "no prometheus_instance")

    def service_row(s):
        pooled = Samples()
        for c in s.url_checks.all():
            smp = samples.get(("url", c.pk))
            if smp:
                pooled.merge(smp)
            pooled.base_ms = c.degraded_ms if pooled.base_ms is None else min(pooled.base_ms, c.degraded_ms)
        for d in s.domains.all():
            smp = samples.get(("domain", d.pk))
            if smp:
                pooled.merge(smp)
        m = pooled.metrics()
        insts = inst_map.get(s.pk, [])
        for col in HOST_COLS:
            vals = [host_values[i][col] for i in insts if col in host_values.get(i, {})]
            m[col] = max(vals) if vals else None
        probe_note = "" if (s.url_checks.all() or s.domains.all()) else "no linked checks"
        cells = [_cell(col, m[col], pooled.base_ms, probe_note if col in PROBE_COLS else
                       ("" if insts and not prom_error and prom_on else prom_note)) for col, _l in COLUMNS]
        return {"ci": s, "name": s.name, "cells": cells, "metrics": m, "samples": pooled, "instances": insts,
                "health": services.worst(c["state"] for c in cells), "checks": len(s.url_checks.all()) + len(s.domains.all())}

    rows, domains_tbl = [], []
    for g in groups:
        svc_rows = [service_row(s) for s in g["services"]]
        visible = [r for r in svc_rows if keep(g, r["ci"])]
        pooled = Samples()
        for r in svc_rows:
            pooled.merge(r["samples"])
        gm = pooled.metrics()
        for col in HOST_COLS:
            vals = [r["metrics"][col] for r in svc_rows if r["metrics"][col] is not None]
            gm[col] = max(vals) if vals else None
        gcells = [_cell(col, gm[col], pooled.base_ms) for col, _l in COLUMNS]
        health = services.worst(r["health"] for r in svc_rows)
        dom = {
            "name": g["name"], "ci": g["ci"], "unassigned": g.get("unassigned", False),
            "description": (g["ci"].description if g["ci"] else "") or "",
            "services": len(svc_rows), "health": health, "cls": STATE_CLASS[health],
            "availability": gm["availability"], "errors": gm["errors"], "p95": gm["latency"],
            "hot_errors": grade("errors", gm["errors"]) in ("warning", "critical"),
            "hot_latency": grade("latency", gm["latency"], pooled.base_ms or 1000.0) in ("warning", "critical"),
            "service_rows": svc_rows,
        }
        domains_tbl.append(dom)
        if visible:
            rows.append({"group": g["name"], "cells": gcells, "services": visible, "health": health})

    counts = {h: sum(1 for d in domains_tbl if d["health"] == h) for h in ("healthy", "warning", "critical", "unknown")}
    return {
        "window": window, "window_label": WINDOWS[window][0], "windows": [(k, v[0]) for k, v in WINDOWS.items()],
        "columns": [label for _c, label in COLUMNS], "rows": rows, "domains": domains_tbl, "counts": counts,
        "domain_names": [d["name"] for d in domains_tbl],
        "service_names": sorted({s.name for s in all_services.values()}, key=str.lower),
        "hosts": host_choices, "prometheus": prom_on, "prometheus_error": prom_error,
        "linked_checks": len(check_ids) + len(domain_ids), "service_count": len(all_services),
        "edges": edges, "ci_map": ci_map, "since": since,
    }


def domain_chain(dom, edges, ci_map, health, max_len=6):
    """Longest dependency path among a domain's services and what they rely on (for the mini topology)."""
    members = {r["ci"].pk for r in dom["service_rows"]}
    if dom["ci"] is not None:
        members.add(dom["ci"].pk)
    adj = services.dependency_adjacency(edges)
    best = []

    def dfs(node, path):
        nonlocal best
        if len(path) > len(best):
            best = list(path)
        if len(path) >= max_len:
            return
        for nxt, rt in adj.get(node, ()):
            if nxt in path or nxt not in ci_map:
                continue
            if rt == RelType.PART_OF:
                continue
            path.append(nxt)
            dfs(nxt, path)
            path.pop()

    for start in sorted(members):
        if start in ci_map and ci_map[start].ci_type != CIType.BUSINESS_DOMAIN:
            dfs(start, [start])
    if not best:
        return []
    # draw from the outermost dependency towards the consumer (Exchange -> Market Data -> OMS ...)
    best = list(reversed(best))
    out = []
    for pk in best:
        c = ci_map[pk]
        h = health.get(pk, "unknown")
        out.append({"ci": c, "name": c.name, "icon": c.icon, "state": h, "cls": STATE_CLASS[h], "hot": h == "critical"})
    return out


def health_from_rows(dom_list):
    """{ci pk: state} for every service row in the domain table (used for the chain colours)."""
    out = {}
    for d in dom_list:
        for r in d["service_rows"]:
            out[r["ci"].pk] = r["health"]
    return out


def is_service(ci: ConfigurationItem):
    return ci.ci_type in SERVICE_TYPES
