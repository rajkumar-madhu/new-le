"""Nagios Core status via statusjson.cgi (hostlist + servicelist with details).

Configuration (all optional; the page shows "not connected" until NAGIOS_URL is set):
  settings.NAGIOS_URL       e.g. https://nagios.example.internal/nagios  (…/cgi-bin/statusjson.cgi also accepted)
  settings.NAGIOS_USER      basic-auth user (CGI user with authorized_for_all_hosts/services)
  settings.NAGIOS_PASSWORD  basic-auth password
  settings.NAGIOS_TIMEOUT   seconds (default: PROMETHEUS_TIMEOUT or 10)
The LINKEDEYE_NAGIOS_* environment variables are read as a fallback when the setting is absent.

Responses are cached for CACHE_SECONDS (30 s); failures for ERROR_CACHE_SECONDS.
"""
import base64
import hashlib
import json
import os
import urllib.error
import urllib.parse
import urllib.request

from django.conf import settings
from django.core.cache import cache

from .fmt import from_epoch

CACHE_SECONDS = 30
ERROR_CACHE_SECONDS = 10
MAX_RESPONSE_BYTES = 32 * 1024 * 1024

HOST_STATES = {1: "pending", 2: "up", 4: "down", 8: "unreachable"}
SERVICE_STATES = {1: "pending", 2: "ok", 4: "warning", 8: "unknown", 16: "critical"}
HOST_ORDER = {"down": 0, "unreachable": 1, "pending": 2, "up": 3}
SERVICE_ORDER = {"critical": 0, "warning": 1, "unknown": 2, "pending": 3, "ok": 4}
STATE_TONE = {"up": "ok", "ok": "ok", "down": "crit", "critical": "crit", "unreachable": "crit",
              "warning": "warn", "unknown": "mute", "pending": "mute"}


class NagiosError(Exception):
    pass


def _setting(name, default=""):
    v = getattr(settings, name, None)
    if v in (None, ""):
        v = os.environ.get(f"LINKEDEYE_{name}", default)
    return v


def configured():
    return bool(str(_setting("NAGIOS_URL") or "").strip())


def base_url():
    return str(_setting("NAGIOS_URL") or "").strip()


def statusjson_url():
    url = base_url().rstrip("/")
    if url.endswith("statusjson.cgi"):
        return url
    if url.endswith("/cgi-bin"):
        return url + "/statusjson.cgi"
    return url + "/cgi-bin/statusjson.cgi"


def timeout():
    t = _setting("NAGIOS_TIMEOUT", "") or getattr(settings, "PROMETHEUS_TIMEOUT", 10) or 10
    try:
        return max(1.0, min(60.0, float(t)))
    except (TypeError, ValueError):
        return 10.0


class _SameOriginAuthRedirect(urllib.request.HTTPRedirectHandler):
    """Follow redirects, but never forward the basic-auth header to another scheme, host or port.

    urllib copies every request header (including Authorization) onto the redirected request, so a redirect from
    the Nagios server (or anything answering on NAGIOS_URL) would otherwise hand the NAGIOS_PASSWORD to a
    third party or send it over plain http."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and _origin(new.full_url) != _origin(req.full_url):
            for k in [k for k in new.headers if k.lower() == "authorization"]:
                del new.headers[k]
            new.unredirected_hdrs.pop("Authorization", None)
        return new


def _origin(url):
    p = urllib.parse.urlsplit(url)
    return (p.scheme.lower(), (p.hostname or "").lower(), p.port or {"http": 80, "https": 443}.get(p.scheme.lower()))


_OPENER = urllib.request.build_opener(_SameOriginAuthRedirect)


def _urlopen(req, timeout):
    return _OPENER.open(req, timeout=timeout)


def _get(params):
    if not configured():
        raise NagiosError("Nagios is not connected (set NAGIOS_URL).")
    url = statusjson_url() + "?" + urllib.parse.urlencode(params)
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise NagiosError("NAGIOS_URL must be an http(s) URL.")
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "LinkedEye/telemetry"})
    user, password = _setting("NAGIOS_USER"), _setting("NAGIOS_PASSWORD")
    if user:
        token = base64.b64encode(f"{user}:{password or ''}".encode()).decode()
        req.add_header("Authorization", f"Basic {token}")
    try:
        with _urlopen(req, timeout()) as r:  # noqa: S310 - operator-configured URL
            raw = r.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            raise NagiosError(f"Nagios rejected the credentials (HTTP {e.code}); check NAGIOS_USER / NAGIOS_PASSWORD.") from None
        raise NagiosError(f"Nagios returned HTTP {e.code}.") from None
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise NagiosError(f"Nagios unreachable: {getattr(e, 'reason', e)}") from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise NagiosError("Nagios response is too large.")
    try:
        body = json.loads(raw.decode("utf-8", errors="replace"))
    except ValueError:
        raise NagiosError("Nagios did not return JSON – is NAGIOS_URL pointing at the Nagios Core web root?") from None
    if not isinstance(body, dict):
        # a JSON list / string (proxy, wrong CGI, Nagios XI API…) is not the statusjson.cgi envelope
        raise NagiosError("Unexpected Nagios response – is NAGIOS_URL pointing at the Nagios Core web root?")
    result = body.get("result")
    if not isinstance(result, dict):
        result = {}
    if result.get("type_code", 0) not in (0, "0"):
        raise NagiosError(f"Nagios error: {result.get('message') or result.get('type_text') or 'query failed'}")
    data = body.get("data")
    if not isinstance(data, dict):
        raise NagiosError("Unexpected Nagios response (no data).")
    return body, data


def _state(value, table):
    if isinstance(value, str):
        v = value.strip().lower()
        if v.isdigit():
            return table.get(int(v), "unknown")
        return v if v in table.values() else "unknown"
    if isinstance(value, int):
        return table.get(value, "unknown")
    return "unknown"


def _host_row(name, d):
    if not isinstance(d, dict):
        d = {"status": d}
    return {"name": str(d.get("name") or name), "state": _state(d.get("status"), HOST_STATES),
            "output": str(d.get("plugin_output") or "")[:500], "last_check": from_epoch(d.get("last_check"), ms=True),
            "last_change": from_epoch(d.get("last_state_change"), ms=True),
            "acknowledged": bool(d.get("problem_has_been_acknowledged")),
            "downtime": bool(d.get("scheduled_downtime_depth")), "flapping": bool(d.get("is_flapping")),
            "attempt": d.get("current_attempt"), "max_attempts": d.get("max_attempts"),
            "hard": d.get("state_type") in (1, "1", "hard")}


def _service_row(host, desc, d):
    if not isinstance(d, dict):
        d = {"status": d}
    return {"host": str(d.get("host_name") or host), "service": str(d.get("description") or desc),
            "state": _state(d.get("status"), SERVICE_STATES), "output": str(d.get("plugin_output") or "")[:500],
            "last_check": from_epoch(d.get("last_check"), ms=True), "last_change": from_epoch(d.get("last_state_change"), ms=True),
            "acknowledged": bool(d.get("problem_has_been_acknowledged")),
            "downtime": bool(d.get("scheduled_downtime_depth")), "flapping": bool(d.get("is_flapping")),
            "attempt": d.get("current_attempt"), "max_attempts": d.get("max_attempts"),
            "hard": d.get("state_type") in (1, "1", "hard")}


def fetch_status(use_cache=True):
    """{"hosts": [...], "services": [...], "query_time": dt, "program": str}. Raises NagiosError."""
    key = "telemetry:nagios:v1:" + hashlib.sha1(statusjson_url().encode()).hexdigest()
    if use_cache:
        hit = cache.get(key)
        if hit is not None:
            if "error" in hit:
                raise NagiosError(hit["error"])
            return hit
    try:
        hbody, hdata = _get({"query": "hostlist", "details": "true"})
        _sbody, sdata = _get({"query": "servicelist", "details": "true"})
    except NagiosError as e:
        cache.set(key, {"error": str(e)}, ERROR_CACHE_SECONDS)
        raise
    hostlist = hdata.get("hostlist") or {}
    servicelist = sdata.get("servicelist") or {}
    hosts = [_host_row(n, d) for n, d in hostlist.items()] if isinstance(hostlist, dict) else []
    services = []
    if isinstance(servicelist, dict):
        for h, svcs in servicelist.items():
            if isinstance(svcs, dict):
                services.extend(_service_row(h, s, d) for s, d in svcs.items())
    hosts.sort(key=lambda r: (HOST_ORDER.get(r["state"], 9), r["name"].lower()))
    services.sort(key=lambda r: (SERVICE_ORDER.get(r["state"], 9), r["host"].lower(), r["service"].lower()))
    result = hbody.get("result") if isinstance(hbody.get("result"), dict) else {}
    out = {"hosts": hosts, "services": services, "query_time": from_epoch(result.get("query_time"), ms=True),
           "program": str(result.get("program_version") or "")}
    cache.set(key, out, CACHE_SECONDS)
    return out


def summarize(status):
    hosts, services = status["hosts"], status["services"]
    hc = {k: sum(1 for h in hosts if h["state"] == k) for k in HOST_ORDER}
    sc = {k: sum(1 for s in services if s["state"] == k) for k in SERVICE_ORDER}
    return {
        "hosts": len(hosts), "services": len(services), "host_counts": hc, "service_counts": sc,
        "host_problems": [h for h in hosts if h["state"] in ("down", "unreachable")],
        "service_problems": [s for s in services if s["state"] in ("critical", "warning", "unknown")],
        "unhandled": sum(1 for h in hosts if h["state"] in ("down", "unreachable") and not (h["acknowledged"] or h["downtime"]))
        + sum(1 for s in services if s["state"] in ("critical", "warning", "unknown") and not (s["acknowledged"] or s["downtime"])),
    }
