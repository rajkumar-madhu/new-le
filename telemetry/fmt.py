"""Small formatting / parsing helpers shared by the telemetry services and template tags."""
import math
from datetime import datetime, timezone as dt_timezone

from django.utils.dateparse import parse_datetime


def parse_ts(value):
    """RFC3339 (Alertmanager / Prometheus, up to nanoseconds) -> aware datetime, or None.

    Go's zero time ("0001-01-01T00:00:00Z") and anything before 1971 mean "not set"."""
    if not value or not isinstance(value, str):
        return None
    try:
        dt = parse_datetime(value.strip())
    except (ValueError, TypeError):
        dt = None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=dt_timezone.utc)
    if dt.year < 1971:
        return None
    return dt


def from_epoch(value, ms=False):
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    if ms:
        v /= 1000.0
    if v <= 0 or math.isnan(v):
        return None
    return datetime.fromtimestamp(v, tz=dt_timezone.utc)


def finite(v):
    return v is not None and isinstance(v, (int, float)) and not math.isnan(v) and not math.isinf(v)


def human_bytes(v, suffix="B"):
    if not finite(v):
        return "–"
    v = float(v)
    for unit in ("", "K", "M", "G", "T", "P"):
        if abs(v) < 1024 or unit == "P":
            return f"{v:.0f} {unit}{suffix}" if unit == "" else f"{v:.1f} {unit}{suffix}"
        v /= 1024.0
    return f"{v:.1f} P{suffix}"  # pragma: no cover


def human_rate(v):
    return "–" if not finite(v) else human_bytes(v, "B/s")


def human_duration(seconds):
    if not finite(seconds):
        return "–"
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m"
    if s < 86400:
        return f"{s // 3600}h {s % 3600 // 60}m"
    return f"{s // 86400}d {s % 86400 // 3600}h"


def human_number(v):
    """Compact value for metric tables: 3 significant digits, K/M/G suffixes for big numbers."""
    if v is None or isinstance(v, bool) or not isinstance(v, (int, float)):
        return "–"
    if isinstance(v, float) and math.isnan(v):
        return "NaN"
    if isinstance(v, float) and math.isinf(v):
        return "+Inf" if v > 0 else "-Inf"
    a = abs(v)
    if a >= 1e9:
        return f"{v / 1e9:.3g}G"
    if a >= 1e6:
        return f"{v / 1e6:.3g}M"
    if a >= 1e4:
        return f"{v / 1e3:.3g}K"
    if a == 0 or a >= 1:
        return f"{v:,.2f}".rstrip("0").rstrip(".") if not float(v).is_integer() else f"{int(v):,}"
    return f"{v:.3g}"


def promql_string(value):
    """Quote a label value for a PromQL selector (double-quoted string literal)."""
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


def series_name(metric):
    """{__name__="x", a="b"} -> 'x{a="b"}' (Prometheus' own notation)."""
    metric = dict(metric or {})
    name = metric.pop("__name__", "")
    inner = ", ".join(f'{k}={promql_string(v)}' for k, v in sorted(metric.items()))
    return f"{name}{{{inner}}}" if inner or not name else name
