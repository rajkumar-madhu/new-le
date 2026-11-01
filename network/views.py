import csv
import ipaddress
import re
from urllib.parse import urlencode

from django.conf import settings
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_http_methods, require_POST

from core import prometheus
from core.access import can, require, visible_sites
from core.audit import audit

from . import discovery, jobs, metrics, services
from .forms import ApproveForm, DeviceForm, DiscoveryForm
from .models import TYPE_PAGES, Device, DeviceStatus, DeviceType, DiscoveredHost, DiscoveryRun, Environment

TYPE_INTRO = {
    "switch": "Access, distribution and core switches",
    "router": "WAN, edge and core routers",
    "firewall": "Perimeter and internal firewalls",
    "load_balancer": "Application delivery controllers and load balancers",
    "wireless": "Wireless controllers and access points",
    "physical_server": "Bare-metal servers and appliances",
    "virtual_machine": "Virtual machines and their hypervisor guests",
}
TABS = [("overview", "Overview"), ("interfaces", "Interfaces"), ("traffic", "Traffic"), ("events", "Events"),
        ("configuration", "Configuration")]
CHECK_ALL_LIMIT = 100


# ------------------------------------------------------------------ helpers
def _per_page(request, default=20):
    try:
        return max(5, min(100, int(request.GET.get("per", default))))
    except (TypeError, ValueError):
        return default


def _query(request, *drop):
    q = request.GET.copy()
    for k in ("page",) + drop:
        q.pop(k, None)
    return q


def _wants_json(request):
    return request.headers.get("Accept", "").startswith("application/json")


def _next(request, fallback):
    nxt = request.POST.get("next") or request.GET.get("next") or ""
    if _safe_url(request, nxt):
        return nxt
    return fallback


def _perms(request):
    u = request.user
    return {"can_operate": can(u, "operate"), "can_admin": can(u, "admin")}


def _safe_url(request, url):
    return bool(url) and url_has_allowed_host_and_scheme(url, allowed_hosts={request.get_host()}, require_https=request.is_secure())


def _deny(request, text="You do not have permission to do that.", fallback="network:all"):
    if _wants_json(request):
        return JsonResponse({"error": text}, status=403)
    messages.error(request, text)
    ref = request.META.get("HTTP_REFERER", "")
    return redirect(_next(request, ref if _safe_url(request, ref) else reverse(fallback)))


CSV_FORMULA_CHARS = ("=", "+", "-", "@", "\t", "\r")


def _cell(value):
    """CSV cell safe to open in a spreadsheet: text starting like a formula is prefixed with a quote."""
    if value is None:
        return ""
    if isinstance(value, str) and value.startswith(CSV_FORMULA_CHARS):
        return "'" + value
    return value


def _device(request, pk):
    return get_object_or_404(services.devices_for(request.user), pk=pk)


def _filtered(request, qs, with_type=False):
    g = request.GET
    q = g.get("q", "").strip()
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(mgmt_ip__icontains=q) | Q(vendor__icontains=q) | Q(model__icontains=q)
                       | Q(serial__icontains=q) | Q(tags__icontains=q) | Q(role__icontains=q))
    for param, field in (("site", "site"), ("status", "status"), ("vendor", "vendor"), ("env", "environment")):
        v = g.get(param, "").strip()
        if v:
            qs = qs.filter(**{field: v})
    if with_type and g.get("type") in DeviceType.values:
        qs = qs.filter(device_type=g["type"])
    sort = g.get("sort", "")
    order = {"name": ["name"], "status": ["status", "name"], "site": ["site", "name"], "seen": ["-last_seen", "name"],
             "latency": ["last_latency_ms", "name"], "ip": ["mgmt_ip"]}.get(sort.lstrip("-"))
    if order:
        if sort.startswith("-"):
            order = [o[1:] if o.startswith("-") else "-" + o for o in order]
        qs = qs.order_by(*order)
    return qs


# ------------------------------------------------------------------ lists
@require("view")
def device_list(request, device_type=None):
    base = services.devices_for(request.user)
    if device_type:
        base = base.filter(device_type=device_type)
    counts = services.status_counts(base)
    qs = _filtered(request, base, with_type=device_type is None)
    page = Paginator(qs, _per_page(request)).get_page(request.GET.get("page"))
    ids = [d.pk for d in page]
    avail = services.availability(ids, 24)
    ifs = services.interface_counts(ids)
    for d in page:
        d.avail24 = avail.get(d.pk)
        d.ifs = ifs.get(d.pk)
    total = counts["total"]
    pct = {s: (100.0 * counts[s] / total if total else 0) for s in DeviceStatus.values}
    if device_type:
        url_name, title, icon = TYPE_PAGES[device_type]
        intro = TYPE_INTRO[device_type]
    else:
        url_name, title, icon, intro = "network:all", "All Devices", "network", "Every monitored network device, server and VM"
    vendors = sorted({v for v in base.order_by().values_list("vendor", flat=True).distinct() if v}, key=str.lower)
    sites = sorted({s for s in base.order_by().values_list("site", flat=True).distinct() if s}, key=str.lower)
    groups = []
    key = "site" if device_type else "device_type"
    rows = base.order_by().values(key).annotate(
        total=Count("id"), up=Count("id", filter=Q(status=DeviceStatus.UP)), down=Count("id", filter=Q(status=DeviceStatus.DOWN)))
    if device_type is None:
        by_type = {r["device_type"]: r for r in rows}
        for value, _label in DeviceType.choices:
            r = by_type.get(value)
            if r:
                groups.append({"label": TYPE_PAGES[value][1], "url": reverse(TYPE_PAGES[value][0]), "total": r["total"],
                               "up": r["up"], "down": r["down"], "icon": TYPE_PAGES[value][2]})
    else:
        for r in sorted(rows, key=lambda r: (-r["down"], (r["site"] or "~").lower()))[:8]:
            groups.append({"label": r["site"] or "(No site)", "url": f"?{urlencode({'site': r['site']})}" if r["site"] else "?",
                           "total": r["total"], "up": r["up"], "down": r["down"], "icon": "globe"})
    export_q = _query(request)
    if device_type:
        export_q["type"] = device_type
    ctx = {
        "page": page, "counts": counts, "pct": pct, "device_type": device_type, "title": title, "icon": icon, "intro": intro,
        "list_url": reverse(url_name), "vendors": vendors, "sites": sites, "statuses": DeviceStatus.choices,
        "envs": Environment.choices, "types": DeviceType.choices, "groups": groups,
        "events": services.recent_events(request.user, 8, device_type),
        "donut": {"segments": [{"label": "Up", "value": counts["up"], "color": "#16a34a"},
                               {"label": "Down", "value": counts["down"], "color": "#dc2626"},
                               {"label": "Unknown", "value": counts["unknown"], "color": "#cbd5e1"}],
                  "center": {"value": str(total), "label": "Devices"}},
        "query": _query(request), "export_query": export_q.urlencode(),
        "create_url": reverse("network:create") + (f"?type={device_type}" if device_type else ""),
        "prometheus_on": prometheus.configured(),
        "last_poll": base.exclude(last_checked_at=None).order_by("-last_checked_at").values_list("last_checked_at", flat=True).first(),
        **_perms(request),
    }
    return render(request, "network/list.html", ctx)


def _type_view(device_type):
    def view(request):
        return device_list(request, device_type)
    view.__name__ = f"{device_type}_list"
    return view


switches = _type_view("switch")
routers = _type_view("router")
firewalls = _type_view("firewall")
load_balancers = _type_view("load_balancer")
wireless = _type_view("wireless")
physical_servers = _type_view("physical_server")
virtual_machines = _type_view("virtual_machine")


@require("view")
def export_csv(request):
    qs = _filtered(request, services.devices_for(request.user), with_type=True)
    resp = HttpResponse(content_type="text/csv; charset=utf-8")
    kind = request.GET.get("type") if request.GET.get("type") in DeviceType.values else "all"
    resp["Content-Disposition"] = f'attachment; filename="network-devices-{kind}.csv"'
    w = csv.writer(resp)
    w.writerow(["name", "type", "vendor", "model", "serial", "firmware", "mgmt_ip", "check_port", "site", "role", "environment",
                "status", "last_seen", "last_checked", "latency_ms", "last_error", "prometheus_instance", "uptime_seconds",
                "enabled", "tags", "contact"])
    for d in qs:
        w.writerow([_cell(v) for v in [d.name, d.device_type, d.vendor, d.model, d.serial, d.firmware, d.mgmt_ip, d.check_port, d.site, d.role,
                    d.environment, d.status, d.last_seen.isoformat() if d.last_seen else "",
                    d.last_checked_at.isoformat() if d.last_checked_at else "",
                    "" if d.last_latency_ms is None else d.last_latency_ms, d.last_error, d.prometheus_instance,
                    "" if d.uptime_seconds is None else d.uptime_seconds, "yes" if d.enabled else "no", d.tags, d.contact]])
    return resp


# ------------------------------------------------------------------ detail
@require("view")
def detail(request, pk):
    device = _device(request, pk)
    tab = request.GET.get("tab", "overview")
    if tab not in dict(TABS):
        tab = "overview"
    interfaces = list(device.interfaces.all())
    if_up = sum(1 for i in interfaces if i.oper_status == "up")
    if_down = sum(1 for i in interfaces if i.oper_status in ("down", "lowerLayerDown") and i.admin_status == "up")
    if_admin_down = sum(1 for i in interfaces if i.admin_status == "down")
    ranked = sorted(interfaces, key=lambda i: (i.utilization is None, -(i.utilization or 0), i.if_index))
    has_rates = any(i.utilization is not None or i.in_mbps is not None for i in interfaces)
    top = ranked[:10] if has_rates else interfaces[:10]
    total_in = sum(i.in_mbps or 0 for i in interfaces) if any(i.in_mbps is not None for i in interfaces) else None
    total_out = sum(i.out_mbps or 0 for i in interfaces) if any(i.out_mbps is not None for i in interfaces) else None
    traffic_range = request.GET.get("range", "24h") if request.GET.get("range") in ("24h", "7d") else "24h"
    traffic, traffic_msg = (None, "")
    if tab in ("overview", "traffic"):
        traffic, traffic_msg = metrics.traffic_range(device, 86400 if traffic_range == "24h" else 7 * 86400)
    can_op = services.can_manage(request.user, "operate", device.site)
    if not prometheus.configured() or not device.prometheus_instance:
        metrics_msg = "No metrics source: set LINKEDEYE_PROMETHEUS_URL and the device Prometheus instance."
    elif device.metrics_error:
        metrics_msg = device.metrics_error
    elif not device.metrics_updated_at:
        metrics_msg = "Waiting for the first metrics collection (every 60 s while run_probes is running)."
    else:
        metrics_msg = ""
    ctx = {
        "device": device, "tab": tab, "tabs": TABS, "interfaces": interfaces, "top_interfaces": top,
        "if_up": if_up, "if_down": if_down, "if_admin_down": if_admin_down, "if_total": len(interfaces), "has_rates": has_rates, "total_in": total_in, "total_out": total_out,
        "avail24": services.availability([device.pk], 24).get(device.pk),
        "avail7": services.availability([device.pk], 24 * 7).get(device.pk),
        "avg_latency": services.avg_latency(device), "spark": services.latency_spark(device),
        "avail_chart": services.availability_chart(device), "latency_chart": services.latency_chart(device),
        "traffic": traffic, "traffic_msg": traffic_msg, "traffic_range": traffic_range,
        "prometheus_on": prometheus.configured(), "metrics_msg": metrics_msg,
        "metrics_ok": bool(prometheus.configured() and device.prometheus_instance and device.metrics_updated_at),
        "events": services.events_for(device, 50 if tab == "events" else 6),
        "polls": device.polls.all()[:50] if tab == "events" else [],
        "topology_url": services.topology_url(device), "discovery_url": services.discovery_url(device),
        "can_operate": can_op, "can_admin": services.can_manage(request.user, "admin", device.site),
        "discovered": device.discovered_as.select_related("run").first(),
    }
    if tab == "configuration":
        from core.models import AuditEvent
        ctx["audit_rows"] = AuditEvent.objects.filter(object_type="network.device", object_id=str(device.pk))[:25]
    return render(request, "network/detail.html", ctx)


# ------------------------------------------------------------------ mutations
@require("operate")
@require_http_methods(["GET", "POST"])
def device_form(request, pk=None):
    device = _device(request, pk) if pk else None
    if device and not services.can_manage(request.user, "operate", device.site):
        raise PermissionDenied
    initial = {}
    if not device:
        if request.GET.get("type") in DeviceType.values:
            initial["device_type"] = request.GET["type"]
        if request.GET.get("site"):
            initial["site"] = request.GET["site"]
    form = DeviceForm(request.POST or None, instance=device, initial=initial)
    if request.method == "POST" and form.is_valid():
        site = form.cleaned_data.get("site", "")
        if not services.can_manage(request.user, "operate", site):
            form.add_error("site", "You cannot manage devices on this site.")
        else:
            changed = list(form.changed_data)
            obj = form.save(commit=False)
            obj.tenant_key = settings.LINKEDEYE_TENANT
            if device and {"mgmt_ip", "check_port"} & set(changed):
                obj.consecutive_failures = 0
            if device and "enabled" in changed and not obj.enabled:
                # a device that is no longer checked must not keep counting as up or down
                obj.status, obj.last_error, obj.status_changed_at = DeviceStatus.UNKNOWN, "Monitoring disabled", timezone.now()
            if device and "prometheus_instance" in changed:
                # interfaces and uptime belonged to the previous snmp_exporter target
                obj.uptime_seconds, obj.metrics_updated_at, obj.metrics_error = None, None, ""
                device.interfaces.all().delete()
            if device and "enabled" in changed and obj.enabled and obj.last_error == "Monitoring disabled":
                obj.last_error = ""
            obj.save()
            if device:
                audit(request, "update", obj, changed=changed)
                if obj.enabled and {"enabled", "mgmt_ip", "check_port"} & set(changed):
                    # re-enabled or pointed at a new target: check it now instead of waiting for the poll
                    result = jobs.check_devices([obj])[0]
                    obj.refresh_from_db()
                    messages.success(request, f"Saved “{obj.name}”. Check now – {_check_summary(obj, result)}")
                else:
                    messages.success(request, f"Saved “{obj.name}”.")
            else:
                audit(request, "create", obj, device_type=obj.device_type, mgmt_ip=obj.mgmt_ip, site=obj.site)
                if obj.enabled:
                    jobs.check_devices([obj])
                    obj.refresh_from_db()
                    messages.success(request, f"Added “{obj.name}”. First check: {obj.get_status_display()}"
                                              + (f" ({obj.last_error})" if obj.last_error else "") + ".")
                else:
                    messages.success(request, f"Added “{obj.name}” (monitoring disabled).")
            return redirect(obj.get_absolute_url())
    vendors = sorted({v for v in Device.objects.filter(tenant_key=settings.LINKEDEYE_TENANT).values_list("vendor", flat=True) if v}
                     | {"Cisco", "Juniper", "Arista", "Fortinet", "Palo Alto Networks", "F5", "Aruba", "Dell", "HPE", "VMware"})
    return render(request, "network/form.html", {"form": form, "device": device, "vendors": vendors})


@require("admin")
@require_POST
def device_delete(request, pk):
    device = _device(request, pk)
    if not services.can_manage(request.user, "admin", device.site):
        return _deny(request)
    name, back = device.name, device.type_list_url
    audit(request, "delete", device, name=name, mgmt_ip=device.mgmt_ip, device_type=device.device_type, site=device.site)
    device.delete()
    messages.success(request, f"Deleted “{name}” and its check history.")
    return redirect(back)


def _check_summary(device, result):
    if result.ok:
        return f"{device.name}: {device.get_status_display()} in {result.latency_ms:g} ms"
    if device.status == DeviceStatus.UP and not result.blocked:
        # one failed check does not mark an Up device down (see jobs.DOWN_AFTER_FAILURES)
        return (f"{device.name}: check failed – {result.error}. Still Up: marked down after "
                f"{jobs.DOWN_AFTER_FAILURES} failed checks in a row ({device.consecutive_failures} so far).")
    return f"{device.name}: {device.get_status_display()} – {result.error}"


@require("operate")
@require_POST
def check_now(request, pk):
    device = _device(request, pk)
    if not services.can_manage(request.user, "operate", device.site):
        return _deny(request)
    if not device.enabled:
        text = f"Monitoring is disabled for {device.name}; enable it before running a check."
        if _wants_json(request):
            return JsonResponse({"error": text, "status": device.status}, status=409)
        messages.warning(request, text)
        return redirect(_next(request, device.get_absolute_url()))
    result = jobs.check_devices([device])[0]
    device.refresh_from_db()
    audit(request, "run", device, check="reachability", status=device.status, ok=result.ok,
          latency_ms=result.latency_ms, error=result.error)
    summary = _check_summary(device, result)
    if _wants_json(request):
        return JsonResponse({"status": device.status, "summary": summary, "latency_ms": result.latency_ms, "error": result.error})
    (messages.success if result.ok else messages.warning)(request, summary)
    return redirect(_next(request, device.get_absolute_url()))


@require("operate")
@require_POST
def check_all(request):
    qs = services.devices_for(request.user).filter(enabled=True)
    t = request.POST.get("type") or request.GET.get("type")
    if t in DeviceType.values:
        qs = qs.filter(device_type=t)
    devices = [d for d in qs.order_by("name") if services.can_manage(request.user, "operate", d.site)]
    limited = len(devices) > CHECK_ALL_LIMIT
    devices = devices[:CHECK_ALL_LIMIT]
    results = jobs.check_devices(devices)
    up = sum(1 for r in results if r.ok)
    audit(request, "run", None, object_type="network.device", check="reachability", device_type=t or "all",
          checked=len(results), up=up)
    summary = f"Checked {len(results)} device(s): {up} reachable, {len(results) - up} not reachable."
    if limited:
        summary += f" Only the first {CHECK_ALL_LIMIT} were checked now; the rest are polled every minute."
    if _wants_json(request):
        return JsonResponse({"checked": len(results), "up": up, "summary": summary})
    messages.success(request, summary)
    return redirect(_next(request, reverse("network:all")))


# ------------------------------------------------------------------ discovery
@require("view")
@require_http_methods(["GET", "POST"])
def discovery_view(request):
    runs_qs = _runs_for(request.user)
    can_op = can(request.user, "operate")
    if request.method == "POST":
        if not can_op:
            return _deny(request, fallback="network:discovery")
        form = DiscoveryForm(request.POST)
        if form.is_valid():
            site = form.cleaned_data["site"]
            if site and not services.can_manage(request.user, "operate", site):
                form.add_error("site", "You cannot manage devices on this site.")
            elif DiscoveryRun.objects.filter(tenant_key=settings.LINKEDEYE_TENANT, status__in=["queued", "running"]).count() >= 3:
                form.add_error(None, "Three discovery runs are already in progress. Wait for one to finish.")
            else:
                run = DiscoveryRun.objects.create(
                    tenant_key=settings.LINKEDEYE_TENANT, cidr=form.cleaned_data["cidr"], ports=form.cleaned_data["ports"],
                    site=site, requested_by=request.user, requested_by_name=request.user.get_username())
                audit(request, "discover", run, cidr=run.cidr, ports=run.ports, site=run.site)
                discovery.launch(run)
                messages.success(request, f"Discovery of {run.cidr} started.")
                return redirect(run.get_absolute_url())
    else:
        form = DiscoveryForm(initial={k: request.GET[k] for k in ("cidr", "ports", "site") if request.GET.get(k)})
    page = Paginator(runs_qs, _per_page(request, 10)).get_page(request.GET.get("page"))
    return render(request, "network/discovery.html", {
        "form": form, "page": page, "query": _query(request), "can_operate": can_op,
        "allowed_cidrs": settings.PROBE_ALLOWED_PRIVATE_CIDRS, "active": runs_qs.filter(status__in=["queued", "running"]).exists(),
        "limits": {"prefix": discovery.MAX_V4_PREFIX, "ports": discovery.MAX_PORTS, "timeout": discovery.SCAN_TIMEOUT},
    })


def _runs_for(user):
    """Discovery runs the user may see: runs for their sites, runs without a site and runs they started."""
    qs = DiscoveryRun.objects.filter(tenant_key=settings.LINKEDEYE_TENANT)
    sites = visible_sites(user)
    if sites is None:
        return qs
    return qs.filter(Q(site__in=list(sites) + ["", "All Sites"]) | Q(requested_by=user))


def _run(request, pk):
    return get_object_or_404(_runs_for(request.user), pk=pk)


def _can_manage_run(user, run):
    """Cancel / ignore: the requester, or an operator for the run's site (tenant-wide for runs without a site)."""
    return (run.requested_by_id is not None and run.requested_by_id == user.pk) or services.can_manage(user, "operate", run.site)


def _ip_key(h):
    try:
        a = ipaddress.ip_address(h.ip)
        return (a.version, int(a))
    except ValueError:
        return (9, 0)


@require("view")
def discovery_run(request, pk):
    run = _run(request, pk)
    hosts = sorted(run.hosts.select_related("device"), key=_ip_key)
    show = request.GET.get("show", "")
    if show in ("new", "approved", "ignored", "existing"):
        hosts = [h for h in hosts if h.status == show]
    counts = {s: 0 for s, _ in DiscoveredHost.STATUS}
    for s in run.hosts.values_list("status", flat=True):
        counts[s] += 1
    return render(request, "network/discovery_run.html", {
        "run": run, "hosts": hosts, "counts": counts, "show": show,
        "approve_form": ApproveForm(initial={"site": run.site, "device_type": "switch"}),
        "can_operate": can(request.user, "operate"), "can_manage_run": _can_manage_run(request.user, run),
    })


def _selected_hosts(request, run, statuses=("new",)):
    ids = [i for i in request.POST.getlist("host") if i.isdigit()]
    return list(run.hosts.filter(pk__in=ids, status__in=statuses))


def _unique_name(base):
    t = settings.LINKEDEYE_TENANT
    name, n = base[:150], 2
    while Device.objects.filter(tenant_key=t, name__iexact=name).exists():
        name = f"{base[:140]}-{n}"
        n += 1
    return name


@require("operate")
@require_POST
def discovery_approve(request, pk):
    run = _run(request, pk)
    form = ApproveForm(request.POST, initial={"site": run.site})
    back = run.get_absolute_url()
    if not form.is_valid():
        messages.error(request, "Choose a device type (and a valid site) to approve hosts.")
        return redirect(back)
    site, dtype, prefix = form.cleaned_data["site"], form.cleaned_data["device_type"], form.cleaned_data["name_prefix"].strip()
    if not services.can_manage(request.user, "operate", site):
        return _deny(request, "You cannot add devices on this site.", "network:discovery")
    hosts = _selected_hosts(request, run)
    if not hosts:
        messages.warning(request, "Select at least one new host to approve.")
        return redirect(back)
    now = timezone.now()
    created, existing = [], []
    known = {}
    for d in Device.objects.filter(tenant_key=settings.LINKEDEYE_TENANT, mgmt_ip__in=[h.ip for h in hosts]):
        known.setdefault(d.mgmt_ip.strip(), d)
    for h in hosts:
        dev = known.get(h.ip)
        if dev is not None:
            # approved from another run (or added by hand) since this scan: link it, never duplicate it
            h.status, h.device, h.decided_by_name, h.decided_at = "existing", dev, request.user.get_username(), now
            h.save(update_fields=["status", "device", "decided_by_name", "decided_at"])
            existing.append(h.ip)
            continue
        port = 22 if 22 in h.open_ports else (h.open_ports[0] if h.open_ports else 22)
        dev = Device.objects.create(
            tenant_key=settings.LINKEDEYE_TENANT, name=_unique_name(f"{prefix}{h.ip}"), device_type=dtype, mgmt_ip=h.ip,
            check_port=port, site=site, environment="", tags="discovered",
            description=f"Discovered by run #{run.pk} ({run.cidr}) on {timezone.localtime(run.created_at):%Y-%m-%d}; "
                        f"open ports {h.ports_display}.")
        h.status, h.device, h.decided_by_name, h.decided_at = "approved", dev, request.user.get_username(), now
        h.save(update_fields=["status", "device", "decided_by_name", "decided_at"])
        audit(request, "create", dev, via="discovery", run=run.pk, mgmt_ip=h.ip, device_type=dtype, site=site)
        known[h.ip] = dev
        created.append(dev)
    audit(request, "approve", run, hosts=[d.mgmt_ip for d in created], already_devices=existing, device_type=dtype, site=site)
    text = f"Added {len(created)} device(s) as {dict(DeviceType.choices)[dtype]}."
    if created:
        text += " They are checked within a minute."
    if existing:
        text += f" Skipped {len(existing)} address(es) that are already devices: {', '.join(existing)}."
    (messages.success if created else messages.warning)(request, text)
    return redirect(back)


@require("operate")
@require_POST
def discovery_ignore(request, pk):
    run = _run(request, pk)
    if not _can_manage_run(request.user, run):
        return _deny(request, "You cannot manage discovery runs for this site.", "network:discovery")
    hosts = _selected_hosts(request, run)
    if not hosts:
        messages.warning(request, "Select at least one new host to ignore.")
        return redirect(run.get_absolute_url())
    now = timezone.now()
    run.hosts.filter(pk__in=[h.pk for h in hosts]).update(status="ignored", decided_by_name=request.user.get_username(), decided_at=now)
    audit(request, "ignore", run, hosts=[h.ip for h in hosts])
    messages.success(request, f"Ignored {len(hosts)} host(s).")
    return redirect(run.get_absolute_url())


@require("operate")
@require_POST
def discovery_cancel(request, pk):
    run = _run(request, pk)
    if not _can_manage_run(request.user, run):
        return _deny(request, "You cannot manage discovery runs for this site.", "network:discovery")
    if not run.active:
        messages.warning(request, "This run has already finished.")
        return redirect(run.get_absolute_url())
    DiscoveryRun.objects.filter(pk=run.pk, status__in=["queued", "running"]).update(status="cancelled", finished_at=timezone.now())
    audit(request, "cancel", run, cidr=run.cidr)
    messages.success(request, f"Cancelled the discovery of {run.cidr}.")
    return redirect(run.get_absolute_url())


@require("view")
def interfaces_csv(request, pk):
    device = _device(request, pk)
    resp = HttpResponse(content_type="text/csv; charset=utf-8")
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", device.name).strip("-") or f"device-{device.pk}"
    resp["Content-Disposition"] = f'attachment; filename="{safe}-interfaces.csv"'
    w = csv.writer(resp)
    w.writerow(["if_index", "name", "alias", "type", "admin_status", "oper_status", "speed_mbps", "in_mbps", "out_mbps",
                "utilization_pct", "updated_at"])
    for i in device.interfaces.all():
        w.writerow([_cell(v) for v in [i.if_index, i.name, i.alias, i.if_type, i.admin_status, i.oper_status, _blank(i.speed_mbps),
                    _blank(i.in_mbps), _blank(i.out_mbps), _blank(i.utilization), i.updated_at.isoformat()]])
    return resp


def _blank(v):
    return "" if v is None else v

