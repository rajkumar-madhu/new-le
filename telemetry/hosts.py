"""Infrastructure hosts from Prometheus node_exporter.

Every query goes server-side through core.prometheus; results are cached for CACHE_SECONDS so a page
refresh storm does not hammer Prometheus. Hosts are keyed by their `instance` label.
"""
import hashlib
import logging
import math
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone as dt_timezone

from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

from . import palette as pal, promapi

from .fmt import finite, promql_string

log = logging.getLogger("linkedeye.telemetry")

CACHE_SECONDS = 30
NODE_JOB = 'job=~".*node.*"'
FS_FILTER = 'fstype!~"tmpfs|overlay|squashfs|ramfs|devtmpfs|nsfs|autofs"'
NET_FILTER = 'device!~"lo|veth.*|docker.*|br-.*|virbr.*|cali.*|flannel.*|cni.*|tun.*|vnet.*"'

# instant queries, all aggregated by instance
QUERIES = {
    "up": f"up{{{NODE_JOB}}}",
    "cpu": f'100 * (1 - avg by (instance) (rate(node_cpu_seconds_total{{mode="idle",{NODE_JOB}}}[5m])))',
    "memory": (f"100 * (1 - (node_memory_MemAvailable_bytes{{{NODE_JOB}}}"
               f" / node_memory_MemTotal_bytes{{{NODE_JOB}}}))"),
    "disk": (f'100 * max by (instance) (1 - (node_filesystem_avail_bytes{{mountpoint="/",{FS_FILTER},{NODE_JOB}}}'
             f' / node_filesystem_size_bytes{{mountpoint="/",{FS_FILTER},{NODE_JOB}}}))'),
    "load1": f"node_load1{{{NODE_JOB}}}",
    "cores": f'count by (instance) (node_cpu_seconds_total{{mode="idle",{NODE_JOB}}})',
    "rx": f"sum by (instance) (rate(node_network_receive_bytes_total{{{NET_FILTER},{NODE_JOB}}}[5m]))",
    "tx": f"sum by (instance) (rate(node_network_transmit_bytes_total{{{NET_FILTER},{NODE_JOB}}}[5m]))",
    "uptime": f"node_time_seconds{{{NODE_JOB}}} - node_boot_time_seconds{{{NODE_JOB}}}",
}
SPARK_QUERY = QUERIES["cpu"]
SPARK_SECONDS, SPARK_STEP = 3600, 120

# (warning at, critical at) – overridable with settings.TELEMETRY_HOST_THRESHOLDS = {"cpu": (75, 90), ...}
DEFAULT_THRESHOLDS = {"cpu": (75.0, 90.0), "memory": (80.0, 90.0), "disk": (80.0, 90.0), "load": (1.5, 3.0)}
HEALTH_ORDER = {"down": 0, "critical": 1, "warning": 2, "unknown": 3, "healthy": 4}
HEALTH_LABEL = {"down": "Down", "critical": "Critical", "warning": "Warning", "unknown": "No data", "healthy": "Healthy"}
HEALTH_TONE = {"down": "crit", "critical": "crit", "warning": "warn", "unknown": "mute", "healthy": "ok"}

RANGES = {"1h": ("Last 1 hour", 3600), "6h": ("Last 6 hours", 6 * 3600),
          "24h": ("Last 24 hours", 86400), "7d": ("Last 7 days", 7 * 86400)}


def thresholds():
    t = dict(DEFAULT_THRESHOLDS)
    t.update(getattr(settings, "TELEMETRY_HOST_THRESHOLDS", {}) or {})
    return t


def grade(metric, value):
    """'ok' | 'warn' | 'crit' | 'mute' for one metric value."""
    if not finite(value):
        return "mute"
    warn, crit = thresholds().get(metric, (None, None))
    if warn is None:
        return "ok"
    return "crit" if value >= crit else "warn" if value >= warn else "ok"


def health_of(h):
    if h.get("up") == 0:
        return "down"
    grades = [grade("cpu", h.get("cpu")), grade("memory", h.get("memory")), grade("disk", h.get("disk")),
              grade("load", h.get("load_per_core"))]
    if "crit" in grades:
        return "critical"
    if "warn" in grades:
        return "warning"
    if all(g == "mute" for g in grades):
        return "unknown"
    return "healthy"


def _run_parallel(named_queries, fn):
    """Run {name: promql} concurrently; returns {name: result}. Re-raises the first PrometheusError."""
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(named_queries)))) as pool:
        futures = {name: pool.submit(fn, q) for name, q in named_queries.items()}
        out = {}
        for name, fut in futures.items():
            out[name] = fut.result()
    return out


def _by_instance(rows):
    out = {}
    for r in rows or ():
        inst = (r.get("metric") or {}).get("instance")
        v = r.get("value")
        if inst and finite(v):
            out[inst] = float(v)
    return out


def fetch_hosts(use_cache=True):
    """List of host dicts (one per node_exporter instance). Raises PrometheusError."""
    key = "telemetry:hosts:v1"
    if use_cache:
        hit = cache.get(key)
        if hit is not None:
            return hit
    up_rows = promapi.query(QUERIES["up"])
    if not up_rows:
        cache.set(key, [], CACHE_SECONDS)
        return []
    rest = {k: v for k, v in QUERIES.items() if k != "up"}
    results = _run_parallel(rest, promapi.query)
    values = {k: _by_instance(v) for k, v in results.items()}
    hosts = {}
    for r in up_rows:
        m = r.get("metric") or {}
        inst = m.get("instance")
        if not inst:
            continue
        upv = r.get("value")
        h = hosts.setdefault(inst, {"instance": inst, "job": m.get("job", ""), "up": None})
        # several node jobs may scrape the same instance: it is up if any of them is
        if finite(upv):
            h["up"] = max(h["up"] or 0, int(upv))
    for inst, h in hosts.items():
        for k in rest:
            h[k] = values[k].get(inst)
        cores = h.get("cores")
        h["load_per_core"] = (h["load1"] / cores) if finite(h.get("load1")) and cores else None
        h["health"] = health_of(h)
        h["address"] = inst.rsplit(":", 1)[0] if inst.count(":") == 1 else inst
    out = sorted(hosts.values(), key=lambda h: (HEALTH_ORDER[h["health"]], h["instance"]))
    cache.set(key, out, CACHE_SECONDS)
    return out


def cpu_sparklines(use_cache=True):
    """{instance: [cpu %, ...]} over the last hour (one range query for every host)."""
    key = "telemetry:hosts:spark:v1"
    if use_cache:
        hit = cache.get(key)
        if hit is not None:
            return hit
    out = {}
    for r in promapi.query_range(SPARK_QUERY, SPARK_SECONDS, SPARK_STEP):
        inst = (r.get("metric") or {}).get("instance")
        if inst:
            out[inst] = [round(v, 2) for _t, v in r.get("values", []) if finite(v)]
    cache.set(key, out, CACHE_SECONDS)
    return out


def summarize(hosts):
    n = len(hosts)
    count = {k: sum(1 for h in hosts if h["health"] == k) for k in HEALTH_ORDER}
    up = sum(1 for h in hosts if h.get("up") == 1)

    def avg(field):
        vals = [h[field] for h in hosts if h.get("up") == 1 and finite(h.get(field))]
        return (sum(vals) / len(vals)) if vals else None
    return {"total": n, "up": up, "down": count["down"], "warning": count["warning"], "critical": count["critical"],
            "healthy": count["healthy"], "unknown": count["unknown"], "avg_cpu": avg("cpu"), "avg_memory": avg("memory"),
            "avg_disk": avg("disk"), "counts": count}


def top(hosts, field, n=5):
    rows = [h for h in hosts if finite(h.get(field))]
    return sorted(rows, key=lambda h: -h[field])[:n]


# ----------------------------------------------------------------------------- CMDB join (optional module)
def cmdb_map(instances):
    """{instance: ConfigurationItem} for CIs whose prometheus_instance matches. {} when cmdb is absent."""
    if not instances:
        return {}
    try:
        from django.apps import apps
        CI = apps.get_model("cmdb", "ConfigurationItem")
    except (LookupError, ImportError):
        return {}
    try:
        qs = CI.objects.filter(prometheus_instance__in=list(instances))
        if hasattr(CI, "tenant_key"):
            qs = qs.filter(tenant_key=settings.LINKEDEYE_TENANT)
        return {ci.prometheus_instance: ci for ci in qs.only("pk", "name", "site", "ci_type", "prometheus_instance")}
    except Exception as e:  # cmdb tables missing (not migrated) must not break the page
        log.warning("CMDB lookup failed: %s", e)
        return {}


def ci_url(ci):
    if ci is None:
        return ""
    try:
        from django.urls import reverse
        return reverse("cmdb:item_detail", args=[ci.pk])
    except Exception:
        return ""


# ----------------------------------------------------------------------------- host detail
def host_selector(instance):
    return f"instance={promql_string(instance)}"


def detail_queries(instance):
    sel = host_selector(instance)
    return {
        "up": f"up{{{sel},{NODE_JOB}}}",
        "uname": f"node_uname_info{{{sel}}}",
        "os": f"node_os_info{{{sel}}}",
        "cpu": f'100 * (1 - avg by (instance) (rate(node_cpu_seconds_total{{mode="idle",{sel}}}[5m])))',
        "memory": f"100 * (1 - (node_memory_MemAvailable_bytes{{{sel}}} / node_memory_MemTotal_bytes{{{sel}}}))",
        "mem_total": f"node_memory_MemTotal_bytes{{{sel}}}",
        "disk": (f'100 * max by (instance) (1 - (node_filesystem_avail_bytes{{mountpoint="/",{FS_FILTER},{sel}}}'
                 f' / node_filesystem_size_bytes{{mountpoint="/",{FS_FILTER},{sel}}}))'),
        "load1": f"node_load1{{{sel}}}", "load5": f"node_load5{{{sel}}}", "load15": f"node_load15{{{sel}}}",
        "cores": f'count by (instance) (node_cpu_seconds_total{{mode="idle",{sel}}})',
        "rx": f"sum by (instance) (rate(node_network_receive_bytes_total{{{NET_FILTER},{sel}}}[5m]))",
        "tx": f"sum by (instance) (rate(node_network_transmit_bytes_total{{{NET_FILTER},{sel}}}[5m]))",
        "uptime": f"node_time_seconds{{{sel}}} - node_boot_time_seconds{{{sel}}}",
        "fs_size": f"node_filesystem_size_bytes{{{FS_FILTER},{sel}}}",
        "fs_avail": f"node_filesystem_avail_bytes{{{FS_FILTER},{sel}}}",
    }


def range_queries(instance):
    sel = host_selector(instance)
    return {
        "cpu": f'100 * (1 - avg by (instance) (rate(node_cpu_seconds_total{{mode="idle",{sel}}}[5m])))',
        "memory": f"100 * (1 - (node_memory_MemAvailable_bytes{{{sel}}} / node_memory_MemTotal_bytes{{{sel}}}))",
        "load1": f"node_load1{{{sel}}}", "load5": f"node_load5{{{sel}}}", "load15": f"node_load15{{{sel}}}",
        "rx": f"sum by (instance) (rate(node_network_receive_bytes_total{{{NET_FILTER},{sel}}}[5m]))",
        "tx": f"sum by (instance) (rate(node_network_transmit_bytes_total{{{NET_FILTER},{sel}}}[5m]))",
    }


def _first(rows):
    for r in rows or ():
        if finite(r.get("value")):
            return float(r["value"])
    return None


def fetch_host(instance, range_key="1h", use_cache=True):
    """Everything the host detail page shows. Returns None when Prometheus has no such instance."""
    key = "telemetry:host:v1:" + hashlib.sha1(f"{instance}|{range_key}".encode()).hexdigest()
    if use_cache:
        hit = cache.get(key)
        if hit is not None:
            return hit
    q = detail_queries(instance)
    up_rows = promapi.query(q.pop("up"))
    if not up_rows:
        return None
    inst = _run_parallel(q, promapi.query)
    h = {"instance": instance, "job": (up_rows[0].get("metric") or {}).get("job", ""),
         "up": max(int(r["value"]) for r in up_rows if finite(r.get("value"))) if any(finite(r.get("value")) for r in up_rows) else None}
    for k in ("cpu", "memory", "disk", "load1", "load5", "load15", "cores", "rx", "tx", "uptime", "mem_total"):
        h[k] = _first(inst.get(k))
    h["load_per_core"] = (h["load1"] / h["cores"]) if finite(h.get("load1")) and h.get("cores") else None
    h["health"] = health_of(h)
    uname = (inst.get("uname") or [{}])[0].get("metric", {}) if inst.get("uname") else {}
    osinfo = (inst.get("os") or [{}])[0].get("metric", {}) if inst.get("os") else {}
    h["nodename"] = uname.get("nodename", "")
    h["kernel"] = " ".join(x for x in (uname.get("sysname", ""), uname.get("release", "")) if x)
    h["arch"] = uname.get("machine", "")
    h["os"] = osinfo.get("pretty_name") or osinfo.get("name", "")
    sizes = {(r["metric"].get("mountpoint"), r["metric"].get("device")): r for r in inst.get("fs_size") or []}
    avail = {(r["metric"].get("mountpoint"), r["metric"].get("device")): r.get("value") for r in inst.get("fs_avail") or []}
    fs = []
    for k, r in sizes.items():
        size, free = r.get("value"), avail.get(k)
        if not finite(size) or size <= 0:
            continue
        used_pct = (100.0 * (1 - free / size)) if finite(free) else None
        fs.append({"mountpoint": k[0] or "", "device": k[1] or "", "fstype": r["metric"].get("fstype", ""),
                   "size": size, "avail": free, "used_pct": used_pct, "grade": grade("disk", used_pct)})
    h["filesystems"] = sorted(fs, key=lambda f: f["mountpoint"])[:50]
    h["charts"] = host_charts(instance, range_key)
    cache.set(key, h, CACHE_SECONDS)
    return h


PALETTE = pal.SERIES


def _labels(ts_list, seconds):
    """Axis + tooltip labels in the project's time zone."""
    fmt = "%H:%M" if seconds <= 86400 else "%d %b"
    local = [timezone.localtime(datetime.fromtimestamp(t, tz=dt_timezone.utc)) for t in ts_list]
    return [d.strftime(fmt) for d in local], [d.strftime("%d %b %H:%M") for d in local]


def align(series_list, seconds):
    """[(name, color, [(ts, v)])] -> chart.js data with a shared time axis (missing points are gaps)."""
    stamps = sorted({t for _n, _c, vals in series_list for t, _v in vals})
    labels, tips = _labels(stamps, seconds)
    out = []
    for name, color, vals in series_list:
        m = {t: (round(v, 4) if finite(v) else None) for t, v in vals}
        out.append({"name": name, "color": color, "values": [m.get(t) for t in stamps]})
    return {"labels": labels, "tipLabels": tips, "series": out}


def step_for(seconds, points=240):
    return max(15, int(math.ceil(seconds / points)))


def host_charts(instance, range_key):
    seconds = RANGES.get(range_key, RANGES["1h"])[1]
    step = step_for(seconds)
    rq = range_queries(instance)
    res = _run_parallel(rq, lambda q: promapi.query_range(q, seconds, step))

    def vals(name):
        rows = res.get(name) or []
        return rows[0]["values"] if rows else []
    cpu = align([("CPU", pal.BLUE, vals("cpu"))], seconds)
    cpu.update({"unit": "%", "yMax": 100})
    mem = align([("Memory", pal.PURPLE, vals("memory"))], seconds)
    mem.update({"unit": "%", "yMax": 100})
    load = align([("1m", pal.CORAL, vals("load1")), ("5m", pal.BLUE, vals("load5")),
                  ("15m", pal.STONE, vals("load15"))], seconds)
    net = align([("Receive", pal.TEAL, vals("rx")), ("Transmit", pal.CORAL, vals("tx"))], seconds)
    net["unit"] = "B/s"
    for c in (cpu, mem):
        for s in c["series"]:
            s["area"] = True
    has = {k: any(v is not None for s in c["series"] for v in s["values"])
           for k, c in (("cpu", cpu), ("memory", mem), ("load", load), ("net", net))}
    return {"cpu": cpu, "memory": mem, "load": load, "net": net, "has": has, "range": range_key, "step": step}
