"""HTTPS security scanner for domains.

A scan opens a TLS connection to the domain (through the SSRF policy: the hostname is resolved with
`probes.checks.resolve_allowed` and the connection is pinned to that validated address), sends one
GET request and reads **only the status line and response headers** – the body is never read. It
records the negotiated TLS version and cipher, the certificate issuer and expiry, and the security
headers, then grades the result A–F.

Scans run from the daily job registered in `DomainmonitorConfig.ready()` (every domain is rescanned
once its last scan is 24 hours old) and from the "Scan now" actions on the Security page.
"""
import http.client
import logging
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone as dt_timezone
from urllib.parse import urljoin, urlsplit

from django.conf import settings
from django.db.models import OuterRef, Subquery
from django.utils import timezone

from probes import checks

from .models import Domain, DomainSecurityScan

log = logging.getLogger("linkedeye.domains.security")

SCAN_EVERY = timedelta(hours=24)        # a domain is due for a scheduled scan once its last scan is this old
JOB_INTERVAL = 3600                     # the job wakes hourly and scans only the domains that are due
MAX_PER_RUN = 50                        # bound one job run; the rest are picked up by the next run
RETENTION_DAYS = 180                    # older scans are pruned (the latest scan of a domain is always kept)
MAX_REDIRECTS = 3
HSTS_MIN_AGE = 15552000                 # 180 days
CERT_WARN_DAYS = 30

# key -> (label, severity, weight, recommendation). Severity "critical" forces grade F.
CHECKS = {
    "cert_valid": ("Trusted certificate for the host", "critical", 0,
                   "Install a certificate from a public CA that covers the host name and serve the full intermediate chain."),
    "cert_expiry": ("Certificate valid for 30+ days", "high", 20,
                    "Renew the certificate and automate renewal (e.g. ACME / certbot) so it never gets close to expiry."),
    "tls_version": ("TLS 1.2 or newer", "critical", 0,
                    "Disable SSLv3, TLS 1.0 and TLS 1.1 on the web server or load balancer."),
    "tls13": ("TLS 1.3 supported", "low", 5,
              "Enable TLS 1.3 on the web server or load balancer (OpenSSL 1.1.1+)."),
    "cipher": ("Forward-secret AEAD cipher", "medium", 10,
               "Prefer ECDHE key exchange with AES-GCM or ChaCha20-Poly1305; remove CBC and static-RSA cipher suites."),
    "https_redirect": ("HTTP redirects to HTTPS", "medium", 15,
                       "Answer every plain-HTTP request with a 301 redirect to the same URL on https://."),
    "hsts": ("Strict-Transport-Security", "high", 20,
             "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on every HTTPS response."),
    "csp": ("Content-Security-Policy", "medium", 15,
            "Define a Content-Security-Policy; start with `default-src 'self'` in Report-Only mode and tighten it."),
    "x_frame_options": ("Clickjacking protection", "medium", 10,
                        "Send `X-Frame-Options: DENY` (or SAMEORIGIN), or a CSP `frame-ancestors` directive."),
    "x_content_type_options": ("X-Content-Type-Options: nosniff", "medium", 10,
                               "Send `X-Content-Type-Options: nosniff` to stop MIME-type sniffing."),
    "referrer_policy": ("Referrer-Policy", "low", 5,
                        "Send `Referrer-Policy: strict-origin-when-cross-origin` (or stricter)."),
    "permissions_policy": ("Permissions-Policy", "low", 5,
                           "Send a Permissions-Policy that disables unused features, e.g. `camera=(), microphone=(), geolocation=()`."),
    "server_disclosure": ("No server version disclosure", "low", 5,
                          "Hide product versions: `server_tokens off` (nginx), `ServerTokens Prod` (Apache); drop X-Powered-By."),
}
HEADER_CHECKS = ["hsts", "csp", "x_frame_options", "x_content_type_options", "referrer_policy", "permissions_policy",
                 "server_disclosure"]
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
GRADE_BANDS = [(90, "A"), (80, "B"), (70, "C"), (60, "D"), (50, "E"), (0, "F")]
WEAK_REFERRER = {"unsafe-url", "no-referrer-when-downgrade"}


@dataclass
class ScanData:
    """Raw facts collected by one scan (no judgement yet)."""
    hostname: str
    ip: str = None
    final_url: str = ""
    http_status: int = None
    tls_version: str = ""
    cipher: str = ""
    cert_issuer: str = ""
    cert_subject: str = ""
    cert_expires_at: datetime = None
    cert_valid: bool = None
    cert_error: str = ""
    https_redirect: bool = None
    http_note: str = ""
    headers: dict = field(default_factory=dict)   # lower-case header name -> value
    error: str = ""


# ----------------------------------------------------------------------------------- network
def _name(rdns, *keys):
    values = {k: v for rdn in rdns or () for k, v in rdn}
    for k in keys:
        if values.get(k):
            return values[k]
    return ""


def _https_headers(hostname, ip, port, path, timeout, verify):
    """One pinned HTTPS request; returns (status, headers, location, tls facts). Reads headers only."""
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    conn = checks._PinnedHTTPSConnection(hostname, ip, port, timeout, ctx)
    try:
        conn.request("GET", path, headers={"User-Agent": checks.USER_AGENT, "Accept": "text/html,*/*",
                                           "Connection": "close"})
        sock = conn.sock   # read TLS facts now: getresponse() may hand the socket over to the response
        tls = {"version": sock.version() or "", "cipher": (sock.cipher() or ("",))[0],
               "cert": sock.getpeercert() if verify else {}}
        resp = conn.getresponse()   # status line + headers; the body is never read
        headers = {}
        for k, v in resp.getheaders():
            k = k.lower()
            headers[k] = f"{headers[k]}, {v}" if k in headers else v
        return resp.status, headers, resp.getheader("Location"), tls
    finally:
        conn.close()


def _http_redirects(hostname, timeout):
    """True when plain HTTP redirects to https://, False when it serves content, None when port 80 is closed."""
    try:
        ip = checks.resolve_allowed(hostname, 80)
        conn = checks._PinnedHTTPConnection(hostname, ip, 80, timeout)
        try:
            conn.request("GET", "/", headers={"User-Agent": checks.USER_AGENT, "Connection": "close"})
            resp = conn.getresponse()
            location = resp.getheader("Location") or ""
            status = resp.status
        finally:
            conn.close()
    except (OSError, http.client.HTTPException, checks.ProbeBlocked) as e:
        return None, f"Port 80 not reachable ({type(e).__name__})"
    target = urljoin(f"http://{hostname}/", location) if location else ""
    if status in (301, 302, 303, 307, 308) and target.startswith("https://"):
        return True, f"HTTP {status} → {target[:200]}"
    if status in (301, 302, 303, 307, 308):
        return False, f"HTTP {status} redirects to {target[:200] or 'nowhere'} (not HTTPS)"
    return False, f"HTTP {status} served over plain HTTP"


def scan_host(hostname, port=443, timeout=None):
    """Collect TLS and header facts for https://hostname/. Never raises; failures land in `error`."""
    timeout = timeout or settings.PROBE_TIMEOUT
    data = ScanData(hostname=hostname)
    url = f"https://{hostname}/" if port == 443 else f"https://{hostname}:{port}/"
    try:
        current, verify = url, True
        for hop in range(MAX_REDIRECTS + 1):
            parts = urlsplit(current)
            host, hport = parts.hostname, parts.port or 443
            ip = checks.resolve_allowed(host, hport)
            path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
            try:
                status, headers, location, tls = _https_headers(host, ip, hport, path, timeout, verify)
            except ssl.SSLCertVerificationError as e:
                if hop:
                    raise
                # the certificate is not trusted: record why, then read the headers without verification
                data.cert_valid, data.cert_error = False, (e.verify_message or str(e))[:300]
                verify = False
                status, headers, location, tls = _https_headers(host, ip, hport, path, timeout, verify)
            if hop == 0:
                data.ip, data.tls_version, data.cipher = ip, tls["version"], tls["cipher"]
                cert = tls["cert"]
                if cert:
                    data.cert_valid = True
                    data.cert_issuer = _name(cert.get("issuer"), "organizationName", "commonName")[:255]
                    data.cert_subject = _name(cert.get("subject"), "commonName", "organizationName")[:255]
                    data.cert_expires_at = checks._cert_expiry(cert)
            data.final_url, data.http_status, data.headers = current, status, headers
            target = urljoin(current, location) if location else ""
            if status in (301, 302, 303, 307, 308) and target.startswith("https://") and hop < MAX_REDIRECTS:
                current = target
                continue
            break
    except checks.ProbeBlocked as e:
        data.error = f"Blocked by probe policy: {e}"
    except ssl.SSLCertVerificationError as e:
        data.error = f"TLS certificate invalid after redirect: {e.verify_message or e}"
    except ssl.SSLError as e:
        data.error = f"TLS handshake failed: {e.reason or e}"
    except socket.gaierror as e:
        data.error = f"DNS resolution failed: {e.strerror or e}"
    except socket.timeout:
        data.error = f"Timed out after {timeout:g}s"
    except ConnectionRefusedError:
        data.error = "Connection refused on port 443"
    except (OSError, http.client.HTTPException, ValueError) as e:
        data.error = f"{type(e).__name__}: {e}"
    if not data.error:
        data.https_redirect, data.http_note = _http_redirects(hostname, min(5.0, timeout))
    return data


# ----------------------------------------------------------------------------------- grading
def _hsts_max_age(value):
    m = re.search(r"max-age\s*=\s*\"?(\d+)", value or "", re.I)
    return int(m.group(1)) if m else None


def _csp_allows_unsafe_scripts(csp):
    """True when the directive that governs scripts (script-src, else default-src) allows unsafe-inline/eval."""
    directives = {}
    for part in csp.split(";"):
        bits = part.strip().split()
        if bits:
            directives.setdefault(bits[0].lower(), [b.lower() for b in bits[1:]])
    sources = directives.get("script-src", directives.get("default-src", []))
    return "'unsafe-inline'" in sources or "'unsafe-eval'" in sources


def evaluate(data, now=None):
    """Turn raw facts into (grade, score, findings). Pure function; empty grade when the scan failed."""
    if data.error:
        return "", None, []
    now = now or datetime.now(dt_timezone.utc)
    h = data.headers
    out = []

    def add(key, passed, detail):
        label, severity, _w, rec = CHECKS[key]
        out.append({"key": key, "label": label, "passed": bool(passed), "severity": severity, "detail": detail,
                    "recommendation": "" if passed else rec})

    add("cert_valid", data.cert_valid is not False,
        f"Issued by {data.cert_issuer or 'unknown issuer'}" if data.cert_valid is not False else data.cert_error or "Not trusted")
    days = (data.cert_expires_at - now).days if data.cert_expires_at else None
    if days is None:
        add("cert_expiry", data.cert_valid is not False, "Expiry not readable (certificate not verified)")
    else:
        add("cert_expiry", days >= CERT_WARN_DAYS, f"Expires in {days} days" if days >= 0 else f"Expired {-days} days ago")
    version = data.tls_version or ""
    modern = version in ("TLSv1.2", "TLSv1.3")
    add("tls_version", modern, f"Negotiated {version or 'unknown'}")
    add("tls13", version == "TLSv1.3", f"Negotiated {version or 'unknown'}" + ("" if version == "TLSv1.3" else " – TLS 1.3 not offered"))
    c = (data.cipher or "").upper()
    aead = version == "TLSv1.3" or (("ECDHE" in c or "DHE" in c) and ("GCM" in c or "CHACHA20" in c))
    add("cipher", aead, data.cipher or "unknown")
    if data.https_redirect is None:
        add("https_redirect", True, data.http_note or "Port 80 closed – nothing served over plain HTTP")
    else:
        add("https_redirect", data.https_redirect, data.http_note)
    hsts = h.get("strict-transport-security", "")
    age = _hsts_max_age(hsts)
    if not hsts:
        add("hsts", False, "Header missing")
    elif age is None or age < HSTS_MIN_AGE:
        add("hsts", False, f"max-age {age if age is not None else 'missing'} is below {HSTS_MIN_AGE} (180 days)")
    else:
        add("hsts", True, hsts[:200])
    csp = h.get("content-security-policy", "")
    if csp:
        weak = _csp_allows_unsafe_scripts(csp)
        add("csp", True, ("Present, but allows unsafe-inline/unsafe-eval scripts: " if weak else "") + csp[:200])
    else:
        ro = h.get("content-security-policy-report-only")
        add("csp", False, "Only Content-Security-Policy-Report-Only is sent" if ro else "Header missing")
    xfo = h.get("x-frame-options", "")
    frame_anc = "frame-ancestors" in csp.lower()
    add("x_frame_options", xfo.strip().upper() in ("DENY", "SAMEORIGIN") or frame_anc,
        f"X-Frame-Options: {xfo}" if xfo else ("CSP frame-ancestors" if frame_anc else "Header missing"))
    xcto = h.get("x-content-type-options", "")
    add("x_content_type_options", xcto.strip().lower() == "nosniff", xcto or "Header missing")
    rp = h.get("referrer-policy", "")
    rp_last = rp.split(",")[-1].strip().lower() if rp else ""
    add("referrer_policy", bool(rp) and rp_last not in WEAK_REFERRER, rp or "Header missing")
    pp = h.get("permissions-policy", "") or h.get("feature-policy", "")
    add("permissions_policy", bool(pp), pp[:200] or "Header missing")
    server, powered = h.get("server", ""), h.get("x-powered-by", "")
    leaks = [x for x in (server if re.search(r"\d", server) else "", f"X-Powered-By: {powered}" if powered else "") if x]
    add("server_disclosure", not leaks, "Discloses " + "; ".join(leaks) if leaks else (f"Server: {server}" if server else "No Server header"))

    score = 100 - sum(CHECKS[f["key"]][2] for f in out if not f["passed"])
    score = max(0, score)
    critical = any(not f["passed"] and f["severity"] == "critical" for f in out)
    if days is not None and days < 0:
        critical = True
    grade = next(g for floor, g in GRADE_BANDS if score >= floor)
    if critical:
        grade, score = "F", min(score, 49)
    return grade, score, out


GRADE_ORDER = {g: i for i, g in enumerate("ABCDEF")}


def save_scan(domain, data, now=None):
    """Store one scan and emit an event when the grade changes. Returns the DomainSecurityScan."""
    now = now or timezone.now()
    grade, score, findings = evaluate(data, now)
    previous = domain.security_scans.exclude(grade="").order_by("-scanned_at").first()
    h = data.headers
    days = (data.cert_expires_at - now).days if data.cert_expires_at else None
    scan = DomainSecurityScan.objects.create(
        domain=domain, scanned_at=now, final_url=data.final_url[:500], ip_address=data.ip, http_status=data.http_status,
        tls_version=data.tls_version[:16], cipher=data.cipher[:120], cert_issuer=data.cert_issuer,
        cert_subject=data.cert_subject, cert_expires_at=data.cert_expires_at, cert_days_left=days,
        cert_valid=data.cert_valid, https_redirect=data.https_redirect,
        hsts=h.get("strict-transport-security", "")[:500], csp=h.get("content-security-policy", "")[:5000],
        x_frame_options=h.get("x-frame-options", "")[:200], x_content_type_options=h.get("x-content-type-options", "")[:200],
        referrer_policy=h.get("referrer-policy", "")[:200], permissions_policy=(h.get("permissions-policy", "") or h.get("feature-policy", ""))[:5000],
        server=h.get("server", "")[:200], grade=grade, score=score, findings=findings, error=data.error[:500])
    if grade and previous and previous.grade != grade:
        worse = GRADE_ORDER[grade] > GRADE_ORDER[previous.grade]
        severity = ("warning" if grade in "DEF" else "info") if worse else "ok"
        try:
            from core.events import emit
            failed = ", ".join(f["label"] for f in findings if not f["passed"])[:400]
            emit("domainmonitor", f"{domain.hostname} security grade {previous.grade} → {grade}", severity=severity,
                 message=f"Failing checks: {failed}" if failed else "All checks pass", site=domain.site_key, obj=domain,
                 fingerprint=f"domainsec:{domain.pk}", kind="security_grade", previous=previous.grade, grade=grade,
                 score=score)
        except Exception:  # an event problem must not lose the scan
            log.exception("could not emit security grade event for %s", domain.hostname)
    return scan


def _safe_scan(domain):
    try:
        return scan_host(domain.hostname)
    except Exception as e:   # one broken scan must not lose the results of the others
        log.exception("security scan of %s failed", domain.hostname)
        return ScanData(hostname=domain.hostname, error=f"Scan failed: {type(e).__name__}: {e}"[:500])


def run_scans(domains, now=None):
    """Scan domains in a thread pool (network only); database writes stay on the calling thread."""
    domains = list(domains)
    if not domains:
        return []
    with ThreadPoolExecutor(max_workers=max(1, min(settings.PROBE_WORKERS, len(domains)))) as pool:
        raw = list(pool.map(_safe_scan, domains))
    now = now or timezone.now()
    return [save_scan(d, r, now) for d, r in zip(domains, raw)]


# ----------------------------------------------------------------------------------- queries
def latest_scans(domain_ids):
    """{domain_id: latest DomainSecurityScan} for the given domains."""
    ids = list(domain_ids)
    if not ids:
        return {}
    newest = DomainSecurityScan.objects.filter(domain=OuterRef("pk")).order_by("-scanned_at", "-pk").values("pk")[:1]
    scan_ids = [i for i in Domain.objects.filter(pk__in=ids).annotate(sid=Subquery(newest)).values_list("sid", flat=True) if i]
    return {s.domain_id: s for s in DomainSecurityScan.objects.filter(pk__in=scan_ids)}


def due_domains(now=None, limit=MAX_PER_RUN):
    now = now or timezone.now()
    last = DomainSecurityScan.objects.filter(domain=OuterRef("pk")).order_by("-scanned_at").values("scanned_at")[:1]
    qs = (Domain.objects.filter(tenant_key=settings.LINKEDEYE_TENANT, is_active=True, monitor_enabled=True)
          .annotate(last_scan=Subquery(last)).order_by("last_scan", "hostname"))
    due = [d for d in qs if d.last_scan is None or now - d.last_scan >= SCAN_EVERY]
    return due[:limit]


def prune(now=None):
    now = now or timezone.now()
    keep = set(s.pk for s in latest_scans(Domain.objects.values_list("pk", flat=True)).values())
    old = DomainSecurityScan.objects.filter(scanned_at__lt=now - timedelta(days=RETENTION_DAYS)).exclude(pk__in=keep)
    return old.delete()[0]


def scheduled_scan():
    """Job body for `manage.py run_probes`: idempotent, bounded, never raises."""
    try:
        domains = due_domains()
        scans = run_scans(domains)
        pruned = prune()
        graded = sum(1 for s in scans if s.grade)
        return f"scanned {len(scans)} domain(s), {graded} graded, pruned {pruned}"
    except Exception:
        log.exception("domain security scan job failed")
        return "error"
