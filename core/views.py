from django.conf import settings
from django.db.models import Q
from django.http import JsonResponse
from django.shortcuts import render
from django.utils.text import capfirst

from domainmonitor.models import Domain
from urlchecker.models import UrlCheck, UrlResult
from urlchecker.stats import overall_uptime

from .samples import exporters as s_exporters, firewall as s_firewall, heatmap as s_heatmap, incidents as s_incidents
from .nav import NAV


def dashboard(request):
    t = settings.LINKEDEYE_TENANT
    urls = list(UrlCheck.objects.filter(tenant_key=t, enabled=True))
    domains = list(Domain.objects.filter(tenant_key=t, is_active=True))
    problems = ([{"kind": "URL", "name": c.name, "status": c.last_status, "detail": c.last_error, "when": c.last_checked_at,
                  "href": f"/monitoring/url-checker/{c.pk}/"} for c in urls if c.last_status in ("down", "degraded")]
                + [{"kind": "Domain", "name": d.hostname, "status": d.status if d.status == "down" else d.ssl_status,
                    "detail": d.last_error or f"SSL {d.ssl_status}", "when": d.last_checked_at, "href": f"/domains/list/?selected={d.pk}"}
                   for d in domains if d.status == "down" or d.ssl_status in ("Expiring", "Expired", "Invalid")])
    return render(request, "core/dashboard.html", {
        "urls_total": len(urls), "urls_online": sum(c.last_status == "online" for c in urls),
        "domains_total": len(domains), "domains_up": sum(d.status == "up" for d in domains),
        "ssl_soon": sum(d.ssl_status in ("Expiring", "Expired") for d in domains),
        "uptime7": overall_uptime(urls, 24 * 7), "problems": problems,
        "events": UrlResult.objects.filter(url_check__tenant_key=t).exclude(status="online").select_related("url_check")[:8],
    })


def search(request):
    q = request.GET.get("q", "").strip()
    t = settings.LINKEDEYE_TENANT
    urls = UrlCheck.objects.filter(tenant_key=t).filter(Q(name__icontains=q) | Q(url__icontains=q) | Q(tags__icontains=q))[:25] if q else []
    domains = Domain.objects.filter(tenant_key=t).filter(Q(hostname__icontains=q) | Q(description__icontains=q))[:25] if q else []
    return render(request, "core/search.html", {"q": q, "urls": urls, "domains": domains})


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
