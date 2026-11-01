"""Runs due URL and domain checks.

Network I/O happens in a thread pool; all database writes happen on the
calling thread, which keeps this safe on SQLite as well as MySQL/PostgreSQL.
"""
import logging
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from core.events import emit
from domainmonitor.models import Domain, DomainCheck
from urlchecker.models import Status, UrlCheck, UrlResult

from . import checks

log = logging.getLogger("linkedeye.probes")


# ---------------------------------------------------------------- URL checks
def evaluate_url(check: UrlCheck, r: checks.HttpResult):
    """Map a raw HTTP result to (status, message)."""
    if not r.ok:
        return Status.DOWN, r.error
    if r.status != check.expected_status:
        return Status.DOWN, f"HTTP {r.status} (expected {check.expected_status})"
    if r.body_matched is False:
        return Status.DOWN, f"Response did not contain “{check.expected_text}”"
    if r.tls_expires_at:
        tls, days = checks.tls_status(r.tls_expires_at)
        if tls == "Expiring" and days < 15:
            return Status.DEGRADED, f"TLS certificate expires in {days} days"
    if r.response_ms > check.degraded_ms:
        return Status.DEGRADED, f"Slow response ({r.response_ms:.0f} ms > {check.degraded_ms} ms)"
    return Status.ONLINE, f"{r.status} OK"


def _probe_url(check):
    return checks.http_check(check.url, method=check.method, timeout=check.timeout_seconds,
                             follow_redirects=check.follow_redirects, expected_text=check.expected_text)


def save_url_result(check, r, now):
    status, message = evaluate_url(check, r)
    UrlResult.objects.create(url_check=check, checked_at=now, status=status, http_status=r.status if r.ok else None,
                             response_ms=r.response_ms if r.ok else None, tls_expires_at=r.tls_expires_at,
                             message=message[:500])
    previous = check.last_status
    check.last_checked_at, check.last_status = now, status
    check.last_http_status = r.status if r.ok else None
    check.last_response_ms = r.response_ms if r.ok else None
    check.last_error = "" if status == Status.ONLINE else message[:500]
    check.save(update_fields=["last_checked_at", "last_status", "last_http_status", "last_response_ms", "last_error"])
    if previous != status:
        log.info("url %s: %s -> %s (%s)", check.name, previous, status, message)
        if previous != Status.UNKNOWN or status != Status.ONLINE:
            sev = {Status.DOWN: "critical", Status.DEGRADED: "warning", Status.ONLINE: "ok"}.get(status, "info")
            emit("urlchecker", f"{check.name} is {status.label if hasattr(status, 'label') else status}", severity=sev,
                 message=message, site=check.site, obj=check, fingerprint=f"url:{check.pk}",
                 previous=str(previous), status=str(status), url=check.url)
    return status


def run_url_checks(items):
    items = list(items)
    if not items:
        return []
    with ThreadPoolExecutor(max_workers=settings.PROBE_WORKERS) as pool:
        raw = list(pool.map(_probe_url, items))
    now = timezone.now()
    return [save_url_result(c, r, now) for c, r in zip(items, raw)]


# ---------------------------------------------------------------- domains
def _probe_domain(domain):
    dns = checks.dns_check(domain.hostname)
    http = checks.http_check(f"https://{domain.hostname}/", method="GET", follow_redirects=True) if dns.ok else None
    tls = checks.tls_check(domain.hostname) if dns.ok else None
    return dns, http, tls


def save_domain_result(domain, probe, now):
    dns, http, tls = probe
    up = bool(http and http.ok and http.status < 500)
    ssl_status = tls.status if tls else "Unknown"
    message = dns.error or (http.error if http and not http.ok else "") or (tls.error if tls and tls.error else "")
    if http and http.ok and http.status >= 500:
        message = f"HTTP {http.status}"
    ip = (http.ip if http and http.ip else (dns.ips[0] if dns.ips else None))
    DomainCheck.objects.create(domain=domain, checked_at=now, up=up, http_status=http.status if http and http.ok else None,
                               response_ms=http.response_ms if up else None, ip_address=ip,
                               dns_status="Resolved" if dns.ok else "Failed", ssl_status=ssl_status,
                               ssl_expires_at=tls.expires_at if tls else None, message=message[:500])
    domain.status = "up" if up else "down"
    domain.dns_status = "Resolved" if dns.ok else "Failed"
    domain.ssl_status = ssl_status
    domain.ip_address = ip
    domain.http_status = http.status if http and http.ok else None
    domain.response_ms = http.response_ms if up else None
    if tls and tls.expires_at:
        domain.ssl_expires_at = tls.expires_at
    previous = domain.status
    domain.last_checked_at = now
    domain.last_error = message[:500]
    domain.save(update_fields=["status", "dns_status", "ssl_status", "ip_address", "http_status", "response_ms",
                               "ssl_expires_at", "last_checked_at", "last_error", "updated_at"])
    if previous != domain.status and not (previous == "unknown" and domain.status == "up"):
        emit("domainmonitor", f"{domain.hostname} is {domain.status}", severity="critical" if domain.status == "down" else "ok",
             message=message, site=domain.site_key, obj=domain, fingerprint=f"domain:{domain.pk}",
             previous=previous, status=domain.status, dns=domain.dns_status, ssl=domain.ssl_status)
    return domain.status


def run_domain_checks(items):
    items = list(items)
    if not items:
        return []
    with ThreadPoolExecutor(max_workers=settings.PROBE_WORKERS) as pool:
        raw = list(pool.map(_probe_domain, items))
    now = timezone.now()
    return [save_domain_result(d, p, now) for d, p in zip(items, raw)]


# ---------------------------------------------------------------- scheduler
def run_due(now=None):
    now = now or timezone.now()
    urls = [c for c in UrlCheck.objects.filter(enabled=True) if c.is_due(now)]
    domains = [d for d in Domain.objects.filter(is_active=True, monitor_enabled=True) if d.is_due(now)]
    run_url_checks(urls)
    run_domain_checks(domains)
    return len(urls), len(domains)


def prune(now=None):
    cutoff = (now or timezone.now()) - timedelta(days=settings.PROBE_RETENTION_DAYS)
    a, _ = UrlResult.objects.filter(checked_at__lt=cutoff).delete()
    b, _ = DomainCheck.objects.filter(checked_at__lt=cutoff).delete()
    return a + b
