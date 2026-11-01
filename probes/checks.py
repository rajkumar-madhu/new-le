"""Network probes used by the URL Checker and Domains modules.

Every probe resolves the target first, validates each resolved address against
the SSRF policy, and then connects to that *validated* address (the hostname is
still sent as Host header and TLS SNI). Pinning the address this way means a
DNS answer cannot change between the policy check and the connection.

Policy:
  * link-local (incl. cloud metadata 169.254.169.254), multicast, unspecified
    and reserved ranges are always refused;
  * loopback and private ranges are refused unless the address falls inside
    settings.PROBE_ALLOWED_PRIVATE_CIDRS (internal monitoring must be opted in).

Probes connect directly; they do not use HTTP(S)_PROXY.
"""
import http.client
import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit

from django.conf import settings

MAX_REDIRECTS = 5
MAX_BODY = 256 * 1024
USER_AGENT = "LinkedEye-Probe/1.0"

ALWAYS_BLOCKED = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
    "::/128", "fe80::/10", "ff00::/8",
)]


class ProbeBlocked(Exception):
    """Target address is not allowed by the probe policy."""


def _allowed_private():
    return [ipaddress.ip_network(c, strict=False) for c in settings.PROBE_ALLOWED_PRIVATE_CIDRS]


def check_address(ip: str) -> None:
    addr = ipaddress.ip_address(ip)
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    if any(addr in n for n in ALWAYS_BLOCKED):
        raise ProbeBlocked(f"{ip} is in a blocked range")
    if addr.is_loopback or addr.is_private or addr.is_reserved or addr.is_link_local:
        if not any(addr in n for n in _allowed_private()):
            raise ProbeBlocked(f"{ip} is a private address not in PROBE_ALLOWED_PRIVATE_CIDRS")


def resolve(host: str, port: int = 443) -> list:
    """Return unique resolved IPs (IPv4 first). Raises socket.gaierror."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    ips = []
    for family, *_rest, sockaddr in sorted(infos, key=lambda i: i[0] != socket.AF_INET):
        if sockaddr[0] not in ips:
            ips.append(sockaddr[0])
    return ips


def resolve_allowed(host: str, port: int) -> str:
    """Resolve and return the first address allowed by policy."""
    ips = resolve(host, port)
    errors = []
    for ip in ips:
        try:
            check_address(ip)
            return ip
        except ProbeBlocked as e:
            errors.append(str(e))
    raise ProbeBlocked("; ".join(errors) or f"{host} did not resolve")


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


def _cert_expiry(cert: dict):
    if not cert or "notAfter" not in cert:
        return None
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)


@dataclass
class HttpResult:
    ok: bool = False                 # transport succeeded and a response was received
    status: int = None               # final HTTP status
    response_ms: float = None        # total time incl. DNS/TCP/TLS and redirects
    ip: str = None
    final_url: str = None
    body_matched: bool = None        # None when no expected text was given
    tls_expires_at: datetime = None
    error: str = ""
    redirects: list = field(default_factory=list)


def http_check(url, method="GET", timeout=None, follow_redirects=True, expected_text=""):
    timeout = timeout or settings.PROBE_TIMEOUT
    res = HttpResult()
    start = time.monotonic()
    current = url
    try:
        for hop in range(MAX_REDIRECTS + 1):
            parts = urlsplit(current)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                raise ValueError(f"unsupported URL: {current}")
            port = parts.port or (443 if parts.scheme == "https" else 80)
            ip = resolve_allowed(parts.hostname, port)
            if parts.scheme == "https":
                conn = _PinnedHTTPSConnection(parts.hostname, ip, port, timeout, ssl.create_default_context())
            else:
                conn = _PinnedHTTPConnection(parts.hostname, ip, port, timeout)
            path = parts.path or "/"
            if parts.query:
                path += "?" + parts.query
            try:
                conn.request(method, path, headers={"User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"})
                resp = conn.getresponse()
                if parts.scheme == "https" and conn.sock is not None:
                    res.tls_expires_at = _cert_expiry(conn.sock.getpeercert())
                body = resp.read(MAX_BODY) if method != "HEAD" else b""
            finally:
                conn.close()
            res.ip, res.status, res.final_url = ip, resp.status, current
            location = resp.getheader("Location")
            if follow_redirects and resp.status in (301, 302, 303, 307, 308) and location and hop < MAX_REDIRECTS:
                res.redirects.append(current)
                current = urljoin(current, location)
                if resp.status == 303:
                    method = "GET"
                continue
            break
        res.ok = True
        if expected_text:
            res.body_matched = expected_text.encode() in body
    except ProbeBlocked as e:
        res.error = f"Blocked by probe policy: {e}"
    except ssl.SSLCertVerificationError as e:
        res.error = f"TLS certificate invalid: {e.verify_message or e}"
    except ssl.SSLError as e:
        res.error = f"TLS error: {e.reason or e}"
    except socket.gaierror as e:
        res.error = f"DNS resolution failed: {e.strerror or e}"
    except socket.timeout:
        res.error = f"Timed out after {timeout:g}s"
    except ConnectionRefusedError:
        res.error = "Connection refused"
    except (OSError, http.client.HTTPException, ValueError) as e:
        res.error = f"{type(e).__name__}: {e}"
    res.response_ms = round((time.monotonic() - start) * 1000, 1)
    return res


@dataclass
class DnsResult:
    ok: bool
    ips: list
    error: str = ""


def dns_check(hostname):
    try:
        return DnsResult(True, resolve(hostname))
    except socket.gaierror as e:
        return DnsResult(False, [], f"DNS resolution failed: {e.strerror or e}")


@dataclass
class TlsResult:
    status: str                      # Valid | Expiring | Expired | Invalid | Unreachable
    expires_at: datetime = None
    days_left: int = None
    issuer: str = ""
    subject: str = ""
    error: str = ""


EXPIRING_DAYS = 30


def tls_status(expires_at, now=None):
    now = now or datetime.now(timezone.utc)
    days = (expires_at - now).days
    return ("Expired" if days < 0 else "Expiring" if days < EXPIRING_DAYS else "Valid"), days


def tls_check(hostname, port=443, timeout=None):
    timeout = timeout or settings.PROBE_TIMEOUT
    try:
        ip = resolve_allowed(hostname, port)
        ctx = ssl.create_default_context()
        with socket.create_connection((ip, port), timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=hostname) as tls:
                cert = tls.getpeercert()
        expires = _cert_expiry(cert)
        status, days = tls_status(expires)
        name = lambda seq: ", ".join("=".join(x) for rdn in seq for x in rdn)  # noqa: E731
        return TlsResult(status, expires, days, name(cert.get("issuer", ())), name(cert.get("subject", ())))
    except ssl.SSLCertVerificationError as e:
        msg = e.verify_message or str(e)
        return TlsResult("Expired" if "expired" in msg.lower() else "Invalid", error=f"TLS certificate invalid: {msg}")
    except ProbeBlocked as e:
        return TlsResult("Unreachable", error=f"Blocked by probe policy: {e}")
    except socket.gaierror as e:
        return TlsResult("Unreachable", error=f"DNS resolution failed: {e.strerror or e}")
    except (OSError, ssl.SSLError) as e:
        return TlsResult("Unreachable", error=f"{type(e).__name__}: {e}")
