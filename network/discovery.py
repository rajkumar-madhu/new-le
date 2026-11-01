"""Subnet discovery: a bounded TCP scan of a small network (IPv4 /24 or smaller,
IPv6 /120 or smaller). Only addresses allowed by the probe policy are contacted.

A run is created as `queued`; `launch()` starts a background thread that claims it
(atomically, queued -> running) and scans. The `network.discovery` job also launches
queued runs that no thread picked up and fails runs that were interrupted."""
import ipaddress
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import timedelta

from django.core.exceptions import ValidationError
from django.db import close_old_connections, connection
from django.utils import timezone

from core.audit import audit

from . import probe

log = logging.getLogger("linkedeye.network")

MAX_V4_PREFIX = 24
MAX_V6_PREFIX = 120
MAX_PORTS = 10
SCAN_TIMEOUT = 1.5          # seconds per TCP connect
SCAN_WORKERS = 32
PROGRESS_EVERY = 16         # hosts between progress saves / cancel checks
STALE_AFTER = timedelta(minutes=20)
_slots = threading.BoundedSemaphore(2)   # concurrent scans per process
_launched = set()                         # run pks with a live scan thread in this process
_launched_lock = threading.Lock()


def parse_cidr(text):
    text = (text or "").strip()
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise ValidationError("Enter a network in CIDR notation, e.g. 10.10.20.0/24.")
    limit = MAX_V4_PREFIX if net.version == 4 else MAX_V6_PREFIX
    if net.prefixlen < limit:
        raise ValidationError(f"The network is too large: use /{limit} or smaller (at most 256 addresses).")
    return net


def parse_ports(text):
    ports = []
    for part in (text or "").replace(" ", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if not part.isdigit() or not 1 <= int(part) <= 65535:
            raise ValidationError(f"“{part}” is not a TCP port (1–65535).")
        if int(part) not in ports:
            ports.append(int(part))
    if not ports:
        raise ValidationError("Enter at least one TCP port, e.g. 22,443.")
    if len(ports) > MAX_PORTS:
        raise ValidationError(f"Scan at most {MAX_PORTS} ports per run.")
    return ports


def addresses(net):
    """Host addresses of the network (the address itself for /32, both for /31)."""
    hosts = list(net.hosts())
    if not hosts:
        hosts = [net.network_address]
    return [str(a) for a in hosts]


def split_allowed(addrs):
    allowed, blocked = [], []
    for a in addrs:
        (allowed if probe.allowed(a) else blocked).append(a)
    return allowed, blocked


def scan_host(ip, ports, timeout=SCAN_TIMEOUT):
    """Return (ip, open ports, best connect latency in ms). Re-validates the address first."""
    if not probe.allowed(ip):
        return ip, [], None
    open_ports, best = [], None
    for port in ports:
        r = probe.connect(ip, port, timeout)
        if r.ok:
            open_ports.append(port)
            best = r.latency_ms if best is None else min(best, r.latency_ms)
    return ip, open_ports, best


def launch(run):
    """Start scanning `run` in a background thread (returns immediately). Returns False when this
    process already has a thread for the run (e.g. still waiting for a scan slot)."""
    with _launched_lock:
        if run.pk in _launched:
            return False
        _launched.add(run.pk)
    t = threading.Thread(target=_thread_main, args=(run.pk,), name=f"network-discovery-{run.pk}", daemon=True)
    try:
        t.start()
    except Exception:
        with _launched_lock:
            _launched.discard(run.pk)
        raise
    return t


def _thread_main(pk):
    try:
        close_old_connections()
        execute(pk)
    except Exception:  # noqa: BLE001 - a background thread must not die noisily
        log.exception("discovery run %s failed", pk)
    finally:
        with _launched_lock:
            _launched.discard(pk)
        connection.close()


def execute(pk):
    """Claim and scan the run. Returns the finished run, or None when another worker owns it."""
    from .models import Device, DiscoveredHost, DiscoveryRun
    with _slots:
        now = timezone.now()
        if not DiscoveryRun.objects.filter(pk=pk, status="queued").update(status="running", started_at=now):
            return None
        run = DiscoveryRun.objects.get(pk=pk)
        try:
            net = parse_cidr(run.cidr)
            ports = parse_ports(run.ports)
            addrs = addresses(net)
            allowed, blocked = split_allowed(addrs)
            run.total_addresses, run.skipped = len(addrs), len(blocked)
            run.save(update_fields=["total_addresses", "skipped"])
            known = {}
            for d in Device.objects.filter(tenant_key=run.tenant_key).only("pk", "mgmt_ip"):
                known.setdefault(d.mgmt_ip.strip(), d)
            scanned = found = 0
            cancelled = False
            with ThreadPoolExecutor(max_workers=min(SCAN_WORKERS, max(1, len(allowed)))) as pool:
                futures = [pool.submit(scan_host, ip, ports) for ip in allowed]
                for fut in as_completed(futures):
                    ip, open_ports, latency = fut.result()
                    scanned += 1
                    if open_ports:
                        found += 1
                        dev = known.get(ip)
                        DiscoveredHost.objects.get_or_create(run=run, ip=ip, defaults={
                            "open_ports": open_ports, "latency_ms": latency, "device": dev,
                            "status": "existing" if dev else "new"})
                    if scanned % PROGRESS_EVERY == 0:
                        DiscoveryRun.objects.filter(pk=pk).update(scanned=scanned, found=found)
                        if _cancelled(pk):
                            cancelled = True
                            for f in futures:
                                f.cancel()
                            break
            run.refresh_from_db()
            run.scanned, run.found, run.finished_at = scanned, found, timezone.now()
            if not cancelled and run.status != "cancelled":
                run.status = "done"
            run.save(update_fields=["scanned", "found", "finished_at", "status"])
            audit(None, "discovery_finished", run, cidr=run.cidr, status=run.status, scanned=scanned,
                  skipped=run.skipped, found=found)
        except ValidationError as e:
            _fail(run, "; ".join(e.messages))
        except Exception as e:  # noqa: BLE001
            log.exception("discovery run %s failed", pk)
            _fail(run, f"{type(e).__name__}: {e}")
        return run


def _cancelled(pk):
    from .models import DiscoveryRun
    return DiscoveryRun.objects.filter(pk=pk, status="cancelled").exists()


def _fail(run, message):
    run.status, run.error, run.finished_at = "failed", message[:300], timezone.now()
    run.save(update_fields=["status", "error", "finished_at"])
    audit(None, "discovery_finished", run, cidr=run.cidr, status="failed", error=run.error)


def tick(launcher=None):
    """Housekeeping from the job loop: start queued runs nobody picked up, fail interrupted ones."""
    from .models import DiscoveryRun
    launcher = launcher or launch
    now = timezone.now()
    stale = DiscoveryRun.objects.filter(status="running", started_at__lt=now - STALE_AFTER)
    failed = 0
    for run in stale:
        _fail(run, "Interrupted: the scan did not finish (the process running it stopped).")
        failed += 1
    started = 0
    for run in DiscoveryRun.objects.filter(status="queued", created_at__lt=now - timedelta(seconds=15)).order_by("created_at")[:2]:
        if launcher(run) is not False:
            started += 1
    if started or failed:
        return f"discovery: started {started}, failed {failed} stale"
    return None
