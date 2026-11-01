from django.conf import settings
from django.db.models import Q
from django.http import JsonResponse
from django.shortcuts import render
from django.utils.text import capfirst

from urlchecker.models import UrlCheck
from urlchecker.stats import overall_uptime

from .access import scope_by_site
from .samples import exporters as s_exporters, firewall as s_firewall, heatmap as s_heatmap, incidents as s_incidents
from .nav import NAV


def dashboard(request):
    from . import overview
    user = request.user
    t = settings.LINKEDEYE_TENANT
    urls = scope_by_site(UrlCheck.objects.filter(tenant_key=t, enabled=True), user)
    return render(request, "core/dashboard.html", {
        "kpis": overview.kpis(user),
        "problems": overview.problems(user, limit=50),
        "events": overview.recent_events(user, limit=10),
        "uptime7": overall_uptime(list(urls), 24 * 7),
        "heatmap_url": overview._url("cmdb:heatmap") or overview._url("heatmap"),
    })


SEARCH_LIMIT = 25


def _search_groups(user, q):
    """[(title, [(label, detail, href)])] across every installed module, limited to the user's sites."""
    from . import overview
    t = settings.LINKEDEYE_TENANT
    groups = []

    def add(title, app_label, name, cond, row, site_field="site"):
        m = overview.model(app_label, name)
        if not m:
            return
        qs = m.objects.filter(cond)
        if hasattr(m, "tenant_key"):
            qs = qs.filter(tenant_key=t)
        if site_field:
            qs = scope_by_site(qs, user, field=site_field)
        rows = overview._safe(lambda: [row(o) for o in qs[:SEARCH_LIMIT]], [])
        groups.append((title, rows))

    add("URL checks", "urlchecker", "UrlCheck", Q(name__icontains=q) | Q(url__icontains=q) | Q(tags__icontains=q),
        lambda c: (c.name, c.url, overview._url("urlchecker:detail", c.pk)))
    add("Domains", "domainmonitor", "Domain", Q(hostname__icontains=q) | Q(description__icontains=q),
        lambda d: (d.hostname, d.site_key, f"{overview._url('domains:list')}?selected={d.pk}"), site_field="site_key")
    add("Network devices", "network", "Device",
        Q(name__icontains=q) | Q(mgmt_ip__icontains=q) | Q(serial__icontains=q) | Q(tags__icontains=q),
        lambda d: (d.name, f"{d.get_device_type_display()} · {d.mgmt_ip}", d.get_absolute_url()))
    add("Tickets", "servicedesk", "Ticket", Q(number__iexact=q) | Q(title__icontains=q) | Q(ci_name__icontains=q),
        lambda k: (f"{k.number} {k.title}", k.get_status_display(), k.get_absolute_url()))
    add("Configuration items", "cmdb", "ConfigurationItem",
        Q(name__icontains=q) | Q(ip_address__icontains=q) | Q(serial__icontains=q) | Q(asset_tag__icontains=q),
        lambda c: (c.name, c.get_ci_type_display(), c.get_absolute_url()))
    add("TCP checks", "tcpcheck", "TcpCheck", Q(name__icontains=q) | Q(host__icontains=q),
        lambda c: (c.name, f"{c.host}:{c.port}", overview._url("tcpcheck:detail", c.pk)))
    add("Runbooks", "automation", "Runbook",
        Q(title__icontains=q) | Q(service__icontains=q) | Q(ci_name__icontains=q) | Q(symptoms__icontains=q) | Q(tags__icontains=q),
        lambda r: (r.title, r.service or r.ci_name, r.get_absolute_url()))
    return groups


def search(request):
    q = request.GET.get("q", "").strip()[:200]
    groups = _search_groups(request.user, q) if q else []
    return render(request, "core/search.html", {"q": q, "groups": groups, "total": sum(len(r) for _, r in groups)})


def heatmap(request):
    return render(request, "core/heatmap.html", {"d": s_heatmap.heatmap(), "sample": True})


def exporters(request):
    return render(request, "core/exporters.html", {"d": s_exporters.exporters(request), "sample": True})


def incidents(request):
    return render(request, "core/incidents.html", {"d": s_incidents.incidents(), "sample": True})


def firewall(request):
    return render(request, "core/firewall.html", {"d": s_firewall.firewall(), "sample": True})


def coming_soon(request, slug):
    from django.utils.text import slugify
    label = next((c["label"] for item in NAV for c in [item, *item.get("children", [])] if slugify(c["label"]) == slug),
                 capfirst(slug.replace("-", " ")))
    return render(request, "core/coming_soon.html", {"label": label})


def healthz(request):
    from django.db import connection
    connection.ensure_connection()
    return JsonResponse({"status": "ok"})
