"""Minimal Prometheus HTTP API client (instant/range queries, targets, alerts).

Only used when settings.PROMETHEUS_URL is set. Queries go server-side; the
browser never talks to Prometheus. Errors raise PrometheusError with a
user-safe message.
"""
import json
import time
import urllib.error
import urllib.parse
import urllib.request

from django.conf import settings


class PrometheusError(Exception):
    pass


def configured():
    return bool(settings.PROMETHEUS_URL)


def _get(path, params=None):
    if not configured():
        raise PrometheusError("Prometheus is not connected (set LINKEDEYE_PROMETHEUS_URL).")
    url = settings.PROMETHEUS_URL.rstrip("/") + path
    if params:
        url += "?" + urllib.parse.urlencode(params, doseq=True)
    try:
        with urllib.request.urlopen(url, timeout=settings.PROMETHEUS_TIMEOUT) as r:  # noqa: S310 - operator-configured URL
            body = json.load(r)
    except urllib.error.HTTPError as e:
        try:
            body = json.load(e)
        except Exception:
            raise PrometheusError(f"Prometheus returned HTTP {e.code}") from None
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise PrometheusError(f"Prometheus unreachable: {getattr(e, 'reason', e)}") from None
    if body.get("status") != "success":
        raise PrometheusError(body.get("error") or "Prometheus query failed")
    return body["data"]


def query(promql, at=None):
    """Instant query -> list of {"metric": {...}, "value": float}."""
    params = {"query": promql}
    if at:
        params["time"] = at
    data = _get("/api/v1/query", params)
    out = []
    for r in data.get("result", []):
        v = r.get("value", [None, None])[1]
        out.append({"metric": r.get("metric", {}), "value": float(v) if v not in (None, "NaN") else None})
    return out


def query_range(promql, seconds=3600, step=None):
    """Range query over the last `seconds` -> list of {"metric", "values": [(ts, float|None)]}."""
    end = time.time()
    step = step or max(15, int(seconds / 120))
    data = _get("/api/v1/query_range", {"query": promql, "start": end - seconds, "end": end, "step": step})
    out = []
    for r in data.get("result", []):
        out.append({"metric": r.get("metric", {}),
                    "values": [(float(t), (float(v) if v != "NaN" else None)) for t, v in r.get("values", [])]})
    return out


def targets():
    return _get("/api/v1/targets").get("activeTargets", [])


def alerts():
    return _get("/api/v1/alerts").get("alerts", [])
