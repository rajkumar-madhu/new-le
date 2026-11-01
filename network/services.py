"""Read-side helpers for the network views: scoping, availability and chart data
computed from stored poll history, and links into other modules."""
from datetime import timedelta
from urllib.parse import urlencode

from django.conf import settings
from django.db.models import Avg, Count, Q
from django.urls import NoReverseMatch, reverse
from django.utils import timezone

from core.access import can, scope_by_site

from .models import Device, DevicePoll, DeviceStatus, Interface


def tenant():
    return settings.LINKEDEYE_TENANT


def devices_for(user):
    return scope_by_site(Device.objects.filter(tenant_key=tenant()), user)


def can_manage(user, perm, site):
    """`perm` on the record's site. Records without a site (or "All Sites") need the
    permission on every site, i.e. a tenant-wide role."""
    if site and site != "All Sites":
        return can(user, perm, site_name=site)
    return can(user, perm) and _tenant_wide(user, perm)


def _tenant_wide(user, perm):
    from core.access import PERMS, RANK, _memberships
    if user.is_superuser:
        return True
    ms = _memberships(user)
    if not ms:  # legacy users without memberships hold their role everywhere
        return True
    return any(m.site is None and RANK[m.role] >= PERMS[perm] for m in ms)


def status_counts(qs):
    rows = qs.order_by().values("status").annotate(n=Count("id"))
    counts = {s: 0 for s in DeviceStatus.values}
    for r in rows:
        counts[r["status"]] = r["n"]
    counts["total"] = sum(counts[s] for s in DeviceStatus.values)
    return counts


def availability(device_ids, hours=24):
    """{device_id: % of checks that found the device up} over the window (None without checks).
    Checks refused by the probe policy (status unknown) are not counted."""
    since = timezone.now() - timedelta(hours=hours)
    rows = (DevicePoll.objects.filter(device_id__in=list(device_ids), checked_at__gte=since)
            .exclude(status=DeviceStatus.UNKNOWN).order_by().values("device_id")
            .annotate(total=Count("id"), up=Count("id", filter=Q(status=DeviceStatus.UP))))
    return {r["device_id"]: round(100.0 * r["up"] / r["total"], 2) for r in rows if r["total"]}


def interface_counts(device_ids):
    rows = (Interface.objects.filter(device_id__in=list(device_ids)).order_by().values("device_id")
            .annotate(total=Count("id"), up=Count("id", filter=Q(oper_status="up"))))
    return {r["device_id"]: (r["up"], r["total"]) for r in rows}


def _hour_buckets(hours):
    now = timezone.localtime().replace(minute=0, second=0, microsecond=0)
    starts = [now - timedelta(hours=hours - 1 - i) for i in range(hours)]
    return starts


def availability_chart(device, hours=24):
    """Stacked bars per hour: checks up / down / refused by policy."""
    starts = _hour_buckets(hours)
    polls = DevicePoll.objects.filter(device=device, checked_at__gte=starts[0]).values_list("checked_at", "status")
    up, down, unk = [0] * hours, [0] * hours, [0] * hours
    for at, st in polls:
        i = int((timezone.localtime(at) - starts[0]).total_seconds() // 3600)
        if 0 <= i < hours:
            (up if st == "up" else down if st == "down" else unk)[i] += 1
    if not any(up) and not any(down) and not any(unk):
        return None
    labels = [s.strftime("%H:%M") for s in starts]
    return {"labels": labels, "tipLabels": [s.strftime("%d %b %H:00") for s in starts], "xLabelEvery": max(1, hours // 6), "yTicks": 2,
            "series": [{"name": "Up", "color": "#16a34a", "values": up},
                       {"name": "Down", "color": "#dc2626", "values": down},
                       {"name": "Not checked (policy)", "color": "#cbd5e1", "values": unk}]}


def latency_chart(device, hours=24):
    """Hourly average connect latency (ms)."""
    starts = _hour_buckets(hours)
    sums, counts = [0.0] * hours, [0] * hours
    for at, ms in DevicePoll.objects.filter(device=device, checked_at__gte=starts[0], latency_ms__isnull=False).values_list("checked_at", "latency_ms"):
        i = int((timezone.localtime(at) - starts[0]).total_seconds() // 3600)
        if 0 <= i < hours:
            sums[i] += ms
            counts[i] += 1
    if not any(counts):
        return None
    vals = [round(sums[i] / counts[i], 1) if counts[i] else None for i in range(hours)]
    return {"labels": [s.strftime("%H:%M") for s in starts], "tipLabels": [s.strftime("%d %b %H:00") for s in starts],
            "unit": "ms", "xLabelEvery": max(1, hours // 6),
            "series": [{"name": "Latency", "color": "#7c3aed", "area": True, "areaOpacity": 0.1, "width": 1.6, "values": vals, "endDot": True}]}


def latency_spark(device, n=40):
    vals = list(DevicePoll.objects.filter(device=device, latency_ms__isnull=False).values_list("latency_ms", flat=True)[:n])
    if len(vals) < 2:
        return None
    return {"values": list(reversed(vals)), "color": "#7c3aed"}


def avg_latency(device, hours=24):
    since = timezone.now() - timedelta(hours=hours)
    v = DevicePoll.objects.filter(device=device, checked_at__gte=since, latency_ms__isnull=False).aggregate(a=Avg("latency_ms"))["a"]
    return round(v, 1) if v is not None else None


def events_for(device, limit=50):
    from core.models import Event
    return Event.objects.filter(tenant_key=device.tenant_key, object_type="network.device", object_id=str(device.pk))[:limit]


def recent_events(user, limit=8, device_type=None):
    from core.models import Event
    qs = scope_by_site(Event.objects.filter(tenant_key=tenant(), source="network"), user)
    if device_type:
        qs = qs.filter(data__device_type=device_type)
    return qs[:limit]


def topology_url(device):
    """CMDB topology centred on the CI with the device's name, when the CMDB has it."""
    try:
        base = reverse("cmdb:topology")
    except NoReverseMatch:
        return None
    try:
        from cmdb.services import find_ci
        ci = find_ci(device.name, device.tenant_key)
    except Exception:  # noqa: BLE001 - CMDB absent or broken: plain topology link
        ci = None
    if ci is not None:
        return f"{base}?{urlencode({'root': ci.pk})}"
    return f"{base}?{urlencode({'q': device.name})}"


def discovery_url(device):
    import ipaddress
    params = {}
    try:
        addr = ipaddress.ip_address(device.mgmt_ip.strip())
        params["cidr"] = str(ipaddress.ip_network(f"{addr}/{24 if addr.version == 4 else 120}", strict=False))
    except ValueError:
        pass
    if device.site:
        params["site"] = device.site
    url = reverse("network:discovery")
    return f"{url}?{urlencode(params)}" if params else url
