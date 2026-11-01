"""Scrape a Prometheus /metrics endpoint and count its samples.

`probes.checks.http_check` validates targets against the probe SSRF policy but does not
return the response body, which is needed here to count samples. This module therefore
follows the same rules as http_check: every hop (including redirects) is resolved and
checked with `checks.resolve_allowed`, and the connection goes to that validated address
(Host header and TLS SNI keep the hostname). The body is streamed and counted without
being kept in memory, with a byte cap and an overall deadline.
"""
import http.client
import re
import socket
import ssl
import time
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from django.conf import settings

from probes import checks

MAX_REDIRECTS = 3
MAX_BYTES = 16 * 1024 * 1024
CHUNK = 64 * 1024
USER_AGENT = "LinkedEye-Exporter-Check/1.0"
ACCEPT = "text/plain;version=0.0.4;q=0.9,application/openmetrics-text;q=0.5,*/*;q=0.1"
# a sample line: metric_name{optional labels} value [timestamp]
SAMPLE_RE = re.compile(rb"^[A-Za-z_:][A-Za-z0-9_:]*(\{.*\})?[ \t]+"
                       rb"(?:[-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?|[-+]?Inf|NaN)(?:[ \t]+-?\d+(?:\.\d+)?)?[ \t]*$")


@dataclass
class ScrapeResult:
    ok: bool = False                 # endpoint answered 2xx with at least one sample
    status: int = None
    response_ms: float = None
    samples: int = 0
    bytes: int = 0
    truncated: bool = False
    error: str = ""


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, ip, port, timeout):
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, ip, port, timeout, context):
        super().__init__(host, port, timeout=timeout, context=context)
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def count_samples(lines_iter):
    """Count Prometheus/OpenMetrics sample lines (comments, blank lines and junk are skipped)."""
    n = 0
    for line in lines_iter:
        line = line.strip()
        if line and not line.startswith(b"#") and SAMPLE_RE.match(line):
            n += 1
    return n


def _read_counting(resp, deadline):
    """Stream the body, counting sample lines. Returns (samples, bytes, truncated)."""
    samples, total, rest = 0, 0, b""
    while True:
        if time.monotonic() > deadline:
            raise TimeoutError("scrape took too long")
        chunk = resp.read(CHUNK)
        if not chunk:
            break
        total += len(chunk)
        data = rest + chunk
        lines = data.split(b"\n")
        rest = lines.pop()
        samples += count_samples(lines)
        if total >= MAX_BYTES:
            return samples, total, True
    if rest:
        samples += count_samples([rest])
    return samples, total, False


def scrape(url, timeout=None):
    timeout = timeout or min(settings.PROBE_TIMEOUT, 10)
    res = ScrapeResult()
    start = time.monotonic()
    deadline = start + timeout * 3
    current = url
    try:
        for hop in range(MAX_REDIRECTS + 1):
            parts = urlsplit(current)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                raise ValueError(f"unsupported URL: {current}")
            port = parts.port or (443 if parts.scheme == "https" else 80)
            ip = checks.resolve_allowed(parts.hostname, port)
            if parts.scheme == "https":
                conn = _PinnedHTTPSConnection(parts.hostname, ip, port, timeout, ssl.create_default_context())
            else:
                conn = _PinnedHTTPConnection(parts.hostname, ip, port, timeout)
            path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
            try:
                conn.request("GET", path, headers={"User-Agent": USER_AGENT, "Accept": ACCEPT, "Connection": "close"})
                resp = conn.getresponse()
                res.status = resp.status
                location = resp.getheader("Location")
                if resp.status in (301, 302, 303, 307, 308) and location and hop < MAX_REDIRECTS:
                    current = urljoin(current, location)
                    continue
                if 200 <= resp.status < 300:
                    res.samples, res.bytes, res.truncated = _read_counting(resp, deadline)
            finally:
                conn.close()
            break
        if res.status is None or not 200 <= res.status < 300:
            res.error = f"HTTP {res.status}" + (f" {http.client.responses.get(res.status, '')}".rstrip() if res.status else "")
        elif res.samples == 0:
            res.error = "No metric samples in the response (is this a /metrics endpoint?)"
        else:
            res.ok = True
    except checks.ProbeBlocked as e:
        res.error = f"Blocked by probe policy: {e}"
    except ssl.SSLCertVerificationError as e:
        res.error = f"TLS certificate invalid: {e.verify_message or e}"
    except ssl.SSLError as e:
        res.error = f"TLS error: {e.reason or e}"
    except socket.gaierror as e:
        res.error = f"DNS resolution failed: {e.strerror or e}"
    except (socket.timeout, TimeoutError):
        res.error = f"Timed out after {timeout:g}s"
    except ConnectionRefusedError:
        res.error = "Connection refused"
    except (OSError, http.client.HTTPException, ValueError) as e:
        res.error = f"{type(e).__name__}: {e}"
    res.response_ms = round((time.monotonic() - start) * 1000, 1)
    return res
