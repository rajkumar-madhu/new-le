"""TCP reachability probe. Every connection goes through the shared SSRF policy
(probes.checks.resolve_allowed / check_address) and connects to the validated
address, so a DNS answer cannot change between the policy check and the connect."""
import socket
import time
from dataclasses import dataclass

from probes import checks


@dataclass
class TcpResult:
    ok: bool
    latency_ms: float = None
    error: str = ""
    blocked: bool = False      # refused by the probe policy (configuration problem, not an outage)
    ip: str = ""


def connect(ip, port, timeout):
    """TCP connect to an address that already passed check_address. Returns TcpResult."""
    start = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            pass
    except socket.timeout:
        return TcpResult(False, error=f"Timed out after {timeout:g}s connecting to port {port}", ip=ip)
    except ConnectionRefusedError:
        return TcpResult(False, error=f"Connection refused on port {port}", ip=ip)
    except OSError as e:
        return TcpResult(False, error=f"{e.strerror or type(e).__name__} (port {port})", ip=ip)
    return TcpResult(True, round((time.monotonic() - start) * 1000, 1), ip=ip)


def tcp_probe(host, port, timeout):
    """Resolve `host`, validate the address against the probe policy and connect to it."""
    try:
        ip = checks.resolve_allowed(host, port)
    except checks.ProbeBlocked as e:
        return TcpResult(False, error=f"Blocked by probe policy: {e}"[:300], blocked=True)
    except socket.gaierror as e:
        return TcpResult(False, error=f"DNS resolution failed: {e.strerror or e}"[:300])
    except (OSError, ValueError) as e:
        return TcpResult(False, error=f"{type(e).__name__}: {e}"[:300])
    return connect(ip, port, timeout)


def allowed(ip):
    """True when the probe policy allows connecting to `ip`."""
    try:
        checks.check_address(ip)
        return True
    except (checks.ProbeBlocked, ValueError):
        return False
