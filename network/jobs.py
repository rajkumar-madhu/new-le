"""Periodic network jobs (registered in NetworkConfig.ready, run by `manage.py run_probes`).

* network.reachability – TCP connect to mgmt_ip:check_port for every enabled device, stores a
  DevicePoll row, updates the device status and emits an event on up <-> down.
* network.metrics – interface rates/states and uptime from Prometheus (snmp_exporter).
* network.discovery – starts queued discovery runs, fails interrupted ones.
Jobs are idempotent, bounded by timeouts and never raise."""
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from core import prometheus
from core.events import emit

from . import discovery, metrics, probe
from .models import Device, DevicePoll, DeviceStatus

log = logging.getLogger("linkedeye.network")

DOWN_AFTER_FAILURES = 2      # an Up device is marked Down after this many failed checks in a row
REACH_TIMEOUT = 5.0          # seconds per TCP connect (capped by PROBE_TIMEOUT)
MAX_WORKERS = 32
_state = {"last_prune": None}


def _tenant():
    return settings.LINKEDEYE_TENANT


def _timeout():
    return min(REACH_TIMEOUT, float(settings.PROBE_TIMEOUT))


# ------------------------------------------------------------------ reachability
def poll_devices():
    try:
        devices = list(Device.objects.filter(tenant_key=_tenant(), enabled=True))
        if not devices:
            return None
        results = check_devices(devices)
        up = sum(1 for d in devices if d.status == DeviceStatus.UP)
        _maybe_prune()
        return f"polled {len(results)} device(s), {up} up"
    except Exception:  # noqa: BLE001 - jobs must not raise
        log.exception("network reachability poll failed")
        return "error"


def check_devices(devices):
    """Probe the devices concurrently, then record the results (DB writes stay on this thread)."""
    devices = list(devices)
    if not devices:
        return []
    timeout = _timeout()
    workers = min(MAX_WORKERS, max(1, settings.PROBE_WORKERS * 2), len(devices))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda d: probe.tcp_probe(d.mgmt_ip.strip(), d.check_port, timeout), devices))
    now = timezone.now()
    for d, r in zip(devices, results):
        try:
            record(d, r, now)
        except Exception:  # noqa: BLE001 - one bad row must not stop the others
            log.exception("could not record poll for device %s", d.pk)
    return results


def record(device, result, now=None):
    """Store one probe result, update the device and emit transition events."""
    now = now or timezone.now()
    prev = device.status
    if result.blocked:
        poll_status, new = DeviceStatus.UNKNOWN, DeviceStatus.UNKNOWN
        device.consecutive_failures = 0
    elif result.ok:
        poll_status, new = DeviceStatus.UP, DeviceStatus.UP
        device.consecutive_failures = 0
        device.last_seen = now
    else:
        poll_status = DeviceStatus.DOWN
        device.consecutive_failures += 1
        # an Up device needs several failures in a row (one lost SYN is not an outage)
        new = DeviceStatus.UP if prev == DeviceStatus.UP and device.consecutive_failures < DOWN_AFTER_FAILURES else DeviceStatus.DOWN
    DevicePoll.objects.create(device=device, checked_at=now, status=poll_status,
                              latency_ms=result.latency_ms if result.ok else None, error=result.error[:300])
    device.status = new
    device.last_checked_at = now
    device.last_latency_ms = result.latency_ms if result.ok else None
    device.last_error = result.error[:300]
    if new != prev:
        device.status_changed_at = now
    device.save(update_fields=["status", "last_checked_at", "last_latency_ms", "last_error", "last_seen",
                               "consecutive_failures", "status_changed_at"])
    if new == DeviceStatus.DOWN and prev != DeviceStatus.DOWN:
        emit(source="network", title=f"{device.name} is down", severity="critical",
             message=f"{device.get_device_type_display()} {device.name} ({device.mgmt_ip}) is not reachable on TCP "
                     f"{device.check_port}: {result.error}",
             site=device.site, obj=device, fingerprint=f"network:{device.pk}",
             ci=device.name, host=device.mgmt_ip, port=device.check_port, device_type=device.device_type, status="down")
    elif new == DeviceStatus.UP and prev == DeviceStatus.DOWN:
        emit(source="network", title=f"{device.name} is up again", severity="ok",
             message=f"{device.get_device_type_display()} {device.name} ({device.mgmt_ip}) answers on TCP {device.check_port} "
                     f"({result.latency_ms:g} ms).",
             site=device.site, obj=device, fingerprint=f"network:{device.pk}",
             ci=device.name, host=device.mgmt_ip, port=device.check_port, device_type=device.device_type, status="up")
    return new


def _maybe_prune():
    if _state["last_prune"] is not None and time.monotonic() - _state["last_prune"] < 3600:
        return 0
    _state["last_prune"] = time.monotonic()
    cutoff = timezone.now() - timedelta(days=settings.PROBE_RETENTION_DAYS)
    removed, _ = DevicePoll.objects.filter(checked_at__lt=cutoff).delete()
    return removed


# ------------------------------------------------------------------ metrics
def collect_metrics():
    try:
        if not prometheus.configured():
            return None
        devices = list(Device.objects.filter(tenant_key=_tenant(), enabled=True).exclude(prometheus_instance=""))
        if not devices:
            return None
        return update_metrics(devices)
    except Exception:  # noqa: BLE001
        log.exception("network metrics collection failed")
        return "error"


def update_metrics(devices):
    by_instance = {}
    for d in devices:
        by_instance.setdefault(d.prometheus_instance.strip(), []).append(d)
    names = list(by_instance)
    updated = 0
    now = timezone.now()
    for i in range(0, len(names), metrics.CHUNK):
        chunk = names[i:i + metrics.CHUNK]
        data, errors = metrics.fetch(chunk)
        for inst in chunk:
            for d in by_instance[inst]:
                try:
                    transitions = metrics.apply(d, data.get(inst), errors, now)
                except Exception:  # noqa: BLE001
                    log.exception("could not store metrics for device %s", d.pk)
                    continue
                updated += 1
                for iface, old, new in transitions:
                    _interface_event(d, iface, old, new)
    return f"metrics for {updated} device(s)"


def _interface_event(device, iface, old, new):
    fp = f"network:{device.pk}:if{iface.if_index}"
    label = f"{device.name} {iface.name}" + (f" ({iface.alias})" if iface.alias else "")
    if new == "up":
        emit(source="network", title=f"Interface {label} is up", severity="ok", message=f"Operational status {old} -> up.",
             site=device.site, obj=device, fingerprint=fp, ci=device.name, interface=iface.name, device_type=device.device_type)
    else:
        emit(source="network", title=f"Interface {label} is down", severity="warning",
             message=f"Operational status {old} -> {new} while administratively up.",
             site=device.site, obj=device, fingerprint=fp, ci=device.name, interface=iface.name, device_type=device.device_type)


# ------------------------------------------------------------------ discovery
def discovery_tick():
    try:
        return discovery.tick()
    except Exception:  # noqa: BLE001
        log.exception("network discovery tick failed")
        return "error"
