"""Helpers shared by the CMDB views."""
import csv

from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.http import HttpResponse
from django.utils.http import url_has_allowed_host_and_scheme

from core.access import can

from .. import services


def per_page(request, default=20):
    try:
        return max(5, min(100, int(request.GET.get("per", default))))
    except (TypeError, ValueError):
        return default


def paginate(request, qs, default=20):
    return Paginator(qs, per_page(request, default)).get_page(request.GET.get("page"))


def query_without_page(request):
    q = request.GET.copy()
    q.pop("page", None)
    return q


def csv_response(filename):
    resp = HttpResponse(content_type="text/csv; charset=utf-8")
    resp["Content-Disposition"] = f'attachment; filename="{filename}"'
    return resp, csv.writer(resp)


def perms(request):
    u = request.user
    return {"can_operate": can(u, "operate"), "can_admin": can(u, "admin")}


def site_checker(request, perm):
    """Cached `site -> bool` for `perm` (rows of a list only offer actions the user may take on that row's site)."""
    cache = {}

    def check(site):
        if site not in cache:
            cache[site] = services.can_manage(request.user, perm, site)
        return cache[site]
    return check


def mark_row_perms(request, rows, site_of=lambda r: r.site):
    """Set row.can_edit / row.can_delete from the user's role on the row's site."""
    edit, delete = site_checker(request, "operate"), site_checker(request, "admin")
    for r in rows:
        site = site_of(r)
        r.can_edit, r.can_delete = edit(site), delete(site)
    return rows


def need_site(request, perm, site):
    """Raise 403 unless the user holds `perm` on `site`."""
    if not services.can_manage(request.user, perm, site):
        raise PermissionDenied


def safe_next(request, fallback):
    nxt = (request.POST.get("next") or request.GET.get("next") or "").strip()
    # same-host paths only: rejects other hosts and javascript:/data: URLs (the value is also echoed into links)
    if nxt and url_has_allowed_host_and_scheme(nxt, allowed_hosts={request.get_host()}, require_https=request.is_secure()):
        return nxt
    return fallback


def days_class(days, warn=90):
    if days is None:
        return "t-mute"
    if days < 0:
        return "t-crit"
    if days <= warn:
        return "t-warn"
    return "t-ok"
