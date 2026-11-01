"""Helpers shared by the CMDB views."""
import csv

from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.http import HttpResponse
from django.shortcuts import redirect
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


def need_site(request, perm, site):
    """Raise 403 unless the user holds `perm` on `site`."""
    if not services.can_manage(request.user, perm, site):
        raise PermissionDenied


def deny(request, text="You do not have permission to do that."):
    messages.error(request, text)
    return redirect(request.META.get("HTTP_REFERER") or "cmdb:items")


def safe_next(request, fallback):
    nxt = request.POST.get("next") or request.GET.get("next") or ""
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
