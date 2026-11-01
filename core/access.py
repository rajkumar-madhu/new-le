"""Role-based access with site scoping.

Roles (lowest to highest): viewer < operator < admin.
  viewer   – read everything on their sites
  operator – also run checks, acknowledge/assign/resolve, add and edit records
  admin    – also manage configuration, users, integrations, deletes
Superusers are admin everywhere. For backwards compatibility a staff user with
no memberships is an operator on all sites, and any other signed-in user with
no memberships is a viewer on all sites.
"""
from functools import wraps

from django.conf import settings
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.http import JsonResponse
from django.shortcuts import redirect

RANK = {"viewer": 1, "operator": 2, "admin": 3}
PERMS = {"view": 1, "operate": 2, "configure": 2, "admin": 3}


def _memberships(user):
    cache = getattr(user, "_le_memberships", None)
    if cache is None:
        from .models import Membership
        cache = list(Membership.objects.filter(user=user).select_related("site"))
        user._le_memberships = cache
    return cache


def role_for(user, site_name=None):
    """Highest role the user holds for the site (or anywhere, when site_name is None)."""
    if not user or not user.is_authenticated:
        return None
    if user.is_superuser:
        return "admin"
    ms = _memberships(user)
    if not ms:
        return "operator" if user.is_staff else "viewer"
    best = None
    for m in ms:
        if m.site is None or site_name is None or m.site.name == site_name:
            if best is None or RANK[m.role] > RANK[best]:
                best = m.role
    return best


def can(user, perm, site_name=None):
    role = role_for(user, site_name)
    return bool(role) and RANK[role] >= PERMS[perm]


def visible_sites(user):
    """None means every site; otherwise the set of site names the user may see."""
    if user.is_superuser:
        return None
    ms = _memberships(user)
    if not ms or any(m.site is None for m in ms):
        return None
    return {m.site.name for m in ms}


def scope_by_site(qs, user, field="site", include_global=("All Sites", "")):
    """Filter a queryset to the user's sites. Records marked 'All Sites' stay visible."""
    sites = visible_sites(user)
    if sites is None:
        return qs
    return qs.filter(**{f"{field}__in": list(sites) + list(include_global)})


def require(perm):
    """View decorator: 403 (JSON for /api/ paths) or redirect with a message when the user lacks `perm`."""
    def deco(view):
        @wraps(view)
        def wrapped(request, *args, **kwargs):
            if can(request.user, perm):
                return view(request, *args, **kwargs)
            if "/api/" in request.path or request.headers.get("Accept", "").startswith("application/json") or request.method == "POST" and request.headers.get("X-CSRFToken"):
                return JsonResponse({"error": f"'{perm}' permission required"}, status=403)
            if request.method == "GET":
                raise PermissionDenied
            messages.error(request, "You do not have permission to do that.")
            return redirect(request.META.get("HTTP_REFERER") or "dashboard")
        wrapped.le_perm = perm
        return wrapped
    return deco


def tenant():
    return settings.LINKEDEYE_TENANT
