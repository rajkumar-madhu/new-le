from django.conf import settings
from django.urls import NoReverseMatch, reverse
from django.utils.text import slugify

from .nav import NAV


def _resolve(item, path):
    if item.get("url"):
        try:
            href = reverse(item["url"])
        except NoReverseMatch:
            href = reverse("coming_soon", args=[slugify(item["label"])])
    else:
        href = reverse("coming_soon", args=[slugify(item["label"])])
    return {"label": item["label"], "icon": item.get("icon"), "href": href, "active": False, "chev": item.get("chev", False)}


def shell(request):
    if not getattr(request, "user", None) or not request.user.is_authenticated:
        return {"le_version": settings.LINKEDEYE_VERSION}
    nav = []
    for item in NAV:
        entry = _resolve(item, request.path)
        entry["children"] = [_resolve(c, request.path) for c in item.get("children", [])]
        nav.append(entry)
    # highlight the single most specific link whose URL prefixes the current path
    links = [e for n in nav for e in [n, *n["children"]]]
    matches = [e for e in links if request.path == e["href"] or (e["href"] != "/" and request.path.startswith(e["href"]))]
    if matches:
        max(matches, key=lambda e: len(e["href"]))["active"] = True
    for entry in nav:
        entry["open"] = entry["active"] or any(c["active"] for c in entry["children"])
    from . import overview
    from .access import role_for
    role = role_for(request.user)
    admin_url = overview._url("administration:index") or overview._url("admin:index")
    return {"nav": nav, "le_version": settings.LINKEDEYE_VERSION,
            "le_problem_count": overview.problem_count(request.user),
            "le_sites": overview.site_names(request.user), "le_site": request.GET.get("site", ""),
            "le_role": "Super Admin" if request.user.is_superuser else (role or "viewer").capitalize(),
            "le_admin_url": admin_url, "le_profile_url": overview._url("administration:profile")}
