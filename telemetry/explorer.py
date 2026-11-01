"""Metrics Explorer: server-side PromQL policy and result shaping.

Policy (enforced before anything is sent to Prometheus):
  * expression: non-empty, at most MAX_QUERY_CHARS characters, no control characters;
  * range: at most MAX_RANGE_SECONDS (7 days);
  * step: raised so that a series never has more than MAX_POINTS points;
  * result: at most MAX_SERIES series are returned to the browser (highest last value first);
  * timeout: the HTTP call uses settings.PROMETHEUS_TIMEOUT (via core.prometheus).
"""
import math
import re

from django.conf import settings

from . import promapi

from .fmt import finite, series_name
from .hosts import PALETTE, align

MAX_QUERY_CHARS = 2000
MAX_RANGE_SECONDS = 7 * 86400
MAX_POINTS = 1100
MAX_SERIES = 40
MIN_STEP = 1

RANGES = [("5m", "5 minutes", 300), ("15m", "15 minutes", 900), ("1h", "1 hour", 3600), ("3h", "3 hours", 3 * 3600),
          ("6h", "6 hours", 6 * 3600), ("12h", "12 hours", 12 * 3600), ("24h", "24 hours", 86400),
          ("2d", "2 days", 2 * 86400), ("7d", "7 days", 7 * 86400)]
RANGE_SECONDS = {k: s for k, _l, s in RANGES}
DEFAULT_RANGE = "1h"
_DURATION = re.compile(r"^\s*(\d+)\s*([smhdw]?)\s*$")
_UNIT = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 7 * 86400}
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

EXAMPLES = [
    ("Targets down", "up == 0"),
    ("CPU busy % by host", '100 * (1 - avg by (instance) (rate(node_cpu_seconds_total{mode="idle"}[5m])))'),
    ("Memory used %", "100 * (1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)"),
    ("Network receive B/s", 'sum by (instance) (rate(node_network_receive_bytes_total{device!="lo"}[5m]))'),
    ("Scrape duration", "scrape_duration_seconds"),
]


class PolicyError(ValueError):
    pass


def parse_duration(value):
    """'90', '90s', '5m', '1h', '2d', '1w' -> seconds (int) or None."""
    if value is None:
        return None
    m = _DURATION.match(str(value))
    if not m:
        return None
    return int(m.group(1)) * _UNIT[m.group(2)]


def min_step(range_seconds):
    """Smallest step that keeps a series at or below MAX_POINTS points (points = range/step + 1)."""
    return max(MIN_STEP, int(math.ceil(range_seconds / (MAX_POINTS - 1))))


def check(promql, range_seconds, step=None):
    """Validate the request; returns (clean_promql, range_seconds, step, notes). Raises PolicyError."""
    promql = (promql or "").strip()
    notes = []
    if not promql:
        raise PolicyError("Enter a PromQL expression.")
    if len(promql) > MAX_QUERY_CHARS:
        raise PolicyError(f"The expression is {len(promql):,} characters; the limit is {MAX_QUERY_CHARS:,}.")
    if _CONTROL.search(promql):
        raise PolicyError("The expression contains control characters.")
    if range_seconds is None or range_seconds <= 0:
        raise PolicyError("Choose a time range.")
    if range_seconds > MAX_RANGE_SECONDS:
        raise PolicyError("The time range is limited to 7 days.")
    floor = min_step(range_seconds)
    if step is None:
        step = max(floor, int(math.ceil(range_seconds / 240)))
    elif step <= 0:
        raise PolicyError("The step must be a positive duration.")
    elif step < floor:
        notes.append(f"Step raised from {step}s to {floor}s to stay within {MAX_POINTS:,} points per series.")
        step = floor
    if step > range_seconds:
        step = range_seconds
        notes.append("Step reduced to the length of the range.")
    return promql, int(range_seconds), int(step), notes


def run(promql, range_seconds, step):
    """Execute a checked query. Returns a result dict for the template. Raises PrometheusError."""
    rows = promapi.query_range(promql, range_seconds, step)
    total = len(rows)

    def last(r):
        for _t, v in reversed(r.get("values") or []):
            if finite(v):
                return v
        return None
    rows = sorted(rows, key=lambda r: (last(r) is None, -(last(r) or 0)))[:MAX_SERIES]
    table, plotted = [], []
    for i, r in enumerate(rows):
        color = PALETTE[i % len(PALETTE)]
        name = series_name(r.get("metric"))
        vals = r.get("values") or []
        lv = last(r)
        last_ts = next((t for t, v in reversed(vals) if finite(v)), None)
        table.append({"name": name, "metric": r.get("metric") or {}, "color": color, "last": lv, "last_ts": last_ts,
                      "min": min((v for _t, v in vals if finite(v)), default=None),
                      "max": max((v for _t, v in vals if finite(v)), default=None),
                      "points": sum(1 for _t, v in vals if finite(v))})
        plotted.append((name, color, vals))
    chart = align(plotted, range_seconds) if plotted else None
    if chart:
        for s in chart["series"]:
            s["width"] = 1.5
    notes = []
    if total > MAX_SERIES:
        notes.append(f"The query returned {total:,} series; showing the {MAX_SERIES} with the highest last value. "
                     "Narrow it with label matchers, sum by (…) or topk().")
    return {"total": total, "series": table, "chart": chart, "notes": notes,
            "timeout": getattr(settings, "PROMETHEUS_TIMEOUT", None)}
