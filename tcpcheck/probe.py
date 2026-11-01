"""TCP / Telnet probe.

Every connection goes through the shared SSRF policy: the host is resolved with
probes.checks.resolve_allowed() and the socket connects to that validated address,
so a DNS answer cannot change between the policy check and the connect.

When a banner is expected the probe reads up to MAX_BANNER bytes within the same
timeout, answers Telnet option negotiation with a refusal (servers often wait for
that before printing their banner) and strips the IAC sequences before matching.
"""
import socket
import time
from dataclasses import dataclass

from probes import checks

MAX_BANNER = 1024

IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240


@dataclass
class ProbeResult:
    ok: bool = False                 # TCP connection established
    response_ms: float = None        # connect time (DNS excluded)
    ip: str = ""
    banner: str = ""                 # printable text received (Telnet negotiation removed)
    banner_matched: bool = None      # None when no banner was expected
    error: str = ""
    blocked: bool = False            # refused by the probe policy (configuration problem)


def parse_telnet(data: bytes):
    """Split raw bytes into (text, replies): text without IAC sequences, and the refusals
    to send back (DO x -> WONT x, WILL x -> DONT x)."""
    text, replies = bytearray(), bytearray()
    i, n = 0, len(data)
    while i < n:
        b = data[i]
        if b != IAC:
            text.append(b)
            i += 1
            continue
        if i + 1 >= n:
            break
        cmd = data[i + 1]
        if cmd == IAC:                       # escaped 0xFF
            text.append(IAC)
            i += 2
        elif cmd in (DO, DONT, WILL, WONT):
            if i + 2 >= n:
                break
            opt = data[i + 2]
            if cmd == DO:
                replies += bytes([IAC, WONT, opt])
            elif cmd == WILL:
                replies += bytes([IAC, DONT, opt])
            i += 3
        elif cmd == SB:                      # sub-negotiation: skip to IAC SE
            end = data.find(bytes([IAC, SE]), i + 2)
            i = n if end < 0 else end + 2
        else:
            i += 2
    return bytes(text), bytes(replies)


def printable(raw: bytes, limit=200):
    s = raw.decode("utf-8", errors="replace")
    s = "".join(ch if ch.isprintable() else " " for ch in s)
    return " ".join(s.split())[:limit]


def read_banner(sock, expect, deadline):
    """Read until `expect` appears, MAX_BANNER bytes arrived, the peer closes, or the deadline passes."""
    raw = bytearray()
    text = b""
    sent = 0  # replies are recomputed from the whole buffer; only the new ones go out (never answer twice)
    while len(raw) < MAX_BANNER:
        left = deadline - time.monotonic()
        if left <= 0:
            break
        sock.settimeout(left)
        try:
            chunk = sock.recv(MAX_BANNER - len(raw))
        except socket.timeout:
            break
        if not chunk:
            break
        raw += chunk
        text, replies = parse_telnet(bytes(raw))
        if len(replies) > sent:
            try:
                sock.sendall(replies[sent:])
            except OSError:
                pass
            sent = len(replies)
        if expect and expect in text.decode("utf-8", errors="replace"):
            break
    if not text and raw:
        text, _ = parse_telnet(bytes(raw))
    return text


def tcp_probe(host, port, timeout, expect_banner=""):
    res = ProbeResult()
    try:
        ip = checks.resolve_allowed(host, port)
    except checks.ProbeBlocked as e:
        res.error, res.blocked = f"Blocked by probe policy: {e}"[:500], True
        return res
    except socket.gaierror as e:
        res.error = f"DNS resolution failed: {e.strerror or e}"[:500]
        return res
    except (OSError, ValueError, UnicodeError) as e:
        res.error = f"{type(e).__name__}: {e}"[:500]
        return res
    res.ip = ip
    start = time.monotonic()
    deadline = start + timeout
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except socket.timeout:
        res.error = f"Timed out after {timeout:g}s connecting to port {port}"
        return res
    except ConnectionRefusedError:
        res.error = f"Connection refused on port {port}"
        return res
    except OSError as e:
        res.error = f"{e.strerror or type(e).__name__} (port {port})"[:500]
        return res
    res.ok = True
    res.response_ms = round((time.monotonic() - start) * 1000, 1)
    try:
        if expect_banner:
            try:
                text = read_banner(sock, expect_banner, deadline)
            except OSError as e:
                text = b""
                res.error = f"Connection lost while reading banner: {e.strerror or type(e).__name__}"[:500]
            res.banner = printable(text)
            res.banner_matched = expect_banner in text.decode("utf-8", errors="replace")
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return res
