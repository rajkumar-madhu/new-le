"""Defensive wrappers around core.prometheus for the telemetry pages.

core.prometheus raises PrometheusError for HTTP/network failures, but a PROMETHEUS_URL that answers with
something other than the Prometheus HTTP API (a Grafana or SSO login page served with HTTP 200, a JSON list,
non-numeric sample values…) surfaces as ValueError / TypeError / AttributeError and turned every telemetry page
into a 500. These wrappers turn such responses into a PrometheusError with a user-safe message, so pages show
their normal error panel instead. The core functions are looked up at call time (tests patch them).
"""
from core import prometheus
from core.prometheus import PrometheusError

BAD_RESPONSE = ("Prometheus returned an unexpected response – is LINKEDEYE_PROMETHEUS_URL the Prometheus server "
                "root (for example http://prometheus:9090) and not a proxy or login page?")
_PARSE_ERRORS = (ValueError, TypeError, AttributeError, KeyError, IndexError)


def _call(fn, *args):
    try:
        return fn(*args)
    except PrometheusError:
        raise
    except _PARSE_ERRORS:
        raise PrometheusError(BAD_RESPONSE) from None


def _dict_rows(rows):
    if not isinstance(rows, list):
        raise PrometheusError(BAD_RESPONSE)
    return [r for r in rows if isinstance(r, dict)]


def query(promql):
    return _dict_rows(_call(prometheus.query, promql))


def query_range(promql, seconds, step):
    return _dict_rows(_call(prometheus.query_range, promql, seconds, step))


def targets():
    return _dict_rows(_call(prometheus.targets))


def alerts():
    return _dict_rows(_call(prometheus.alerts))
