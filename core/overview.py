"""Cross-module numbers for the dashboard, the alert badge and the site picker.

Every module is optional: its model is looked up lazily, and a module that is missing (or whose tables are not
migrated) simply contributes nothing. Rows are limited to the user's sites.
"""
from django.apps import apps
from django.conf import settings
from django.core.exceptions import FieldError
from django.db import DatabaseError
from django.urls import NoReverseMatch, reverse

from .access import scope_by_site, visible_sites


def model(app_label, name):
    try:
        return apps.get_model(app_label, name)
    except LookupError:
        return None


def _safe(fn, default):
    try:
        return fn()
    except (DatabaseError, FieldError):
        return default


def _url(name, *args):
    try:
        return reverse(name, args=args)
    except NoReverseMatch:
        return ""


def _tenant(qs):
    return qs.filter(tenant_key=settings.LINKEDEYE_TENANT) if hasattr(qs.model, "tenant_key") else qs


def _scoped(m, user, field="site"):
    qs = _tenant(m.objects.all())
    return scope_by_site(qs, user, field=field) if user is not None else qs


# ------------------------------------------------------------------ problems ("needs attention")
def problems(user, limit=None):
    """Everything currently down or degraded, newest first. Each item: kind, name, status, detail, when, href."""
    out = []
    UrlCheck = model("urlchecker", "UrlCheck")
    if UrlCheck:
        for c in _safe(lambda: list(_scoped(UrlCheck, user).filter(enabled=True, last_status__in=["down", "degraded"])), []):
            out.append({"kind": "URL", "name": c.name, "status": c.last_status, "detail": c.last_error,
                        "when": c.last_checked_at, "href": _url("urlchecker:detail", c.pk), "site": c.site})
    Domain = model("domainmonitor", "Domain")
    if Domain:
        qs = _safe(lambda: list(_scoped(Domain, user, "site_key").filter(is_active=True).exclude(
            status="up", ssl_status__in=["Valid", "Unknown"])), [])
        for d in qs:
            if d.status != "down" and d.ssl_status not in ("Expiring", "Expired", "Invalid"):
                continue
            out.append({"kind": "Domain", "name": d.hostname, "status": d.status if d.status == "down" else d.ssl_status,
                        "detail": d.last_error or f"SSL {d.ssl_status}", "when": d.last_checked_at,
                        "href": f"{_url('domains:list')}?selected={d.pk}", "site": d.site_key})
    Device = model("network", "Device")
    if Device:
        for d in _safe(lambda: list(_scoped(Device, user).filter(enabled=True, status="down")), []):
            out.append({"kind": "Device", "name": d.name, "status": "down", "detail": d.last_error,
                        "when": d.last_checked_at, "href": d.get_absolute_url(), "site": d.site})
    TcpCheck = model("tcpcheck", "TcpCheck")
    if TcpCheck:
        for c in _safe(lambda: list(_scoped(TcpCheck, user).filter(enabled=True, last_status__in=["down", "degraded"])), []):
            out.append({"kind": "TCP", "name": f"{c.name} ({c.host}:{c.port})", "status": c.last_status,
                        "detail": c.last_error, "when": c.last_checked_at, "href": _url("tcpcheck:detail", c.pk),
                        "site": c.site})
    Alert = model("telemetry", "Alert")
    if Alert:
        for a in _safe(lambda: list(_scoped(Alert, user).filter(status="firing", severity="critical")
                                    .order_by("-starts_at")[:50]), []):
            out.append({"kind": "Alert", "name": a.alertname, "status": "critical", "detail": a.summary or a.instance,
                        "when": a.starts_at, "href": _url("telemetry:alert_detail", a.pk), "site": a.site})
    out.sort(key=lambda p: p["when"].timestamp() if p["when"] else 0, reverse=True)
    return out[:limit] if limit else out


def problem_count(user):
    """Same population as problems(), counted in the database (used on every page for the bell badge)."""
    from django.db.models import Q
    total = 0
    checks = [
        ("urlchecker", "UrlCheck", "site", Q(enabled=True, last_status__in=["down", "degraded"])),
        ("domainmonitor", "Domain", "site_key",
         Q(is_active=True) & (Q(status="down") | Q(ssl_status__in=["Expiring", "Expired", "Invalid"]))),
        ("network", "Device", "site", Q(enabled=True, status="down")),
        ("tcpcheck", "TcpCheck", "site", Q(enabled=True, last_status__in=["down", "degraded"])),
        ("telemetry", "Alert", "site", Q(status="firing", severity="critical")),
    ]
    for app_label, name, field, cond in checks:
        m = model(app_label, name)
        if m:
            total += _safe(lambda: _scoped(m, user, field).filter(cond).count(), 0)
    return total


# ------------------------------------------------------------------ KPIs
def kpis(user):
    """Dashboard tiles; a module that is not installed is left out."""
    tiles = []
    Ticket = model("servicedesk", "Ticket")
    if Ticket:
        def incidents():
            qs = _scoped(Ticket, user).filter(kind="incident").open()
            return qs.count(), qs.filter(priority__in=["P1", "P2"]).count()
        n = _safe(incidents, None)
        if n is not None:
            tiles.append({"label": "Incidents", "value": n[0], "sub": f"Open · {n[1]} P1/P2", "icon": "alert",
                          "tile": "s-crit" if n[1] else "s-info", "href": _url("servicedesk:incidents")})
    Alert = model("telemetry", "Alert")
    if Alert:
        n = _safe(lambda: _scoped(Alert, user).filter(status="firing").count(), None)
        if n is not None:
            tiles.append({"label": "Alerts", "value": n, "sub": "Firing in Alertmanager", "icon": "bell",
                          "tile": "s-warn" if n else "s-ok", "href": _url("telemetry:alertmanager")})

    def ratio(label, m, up_q, total_q, icon, href, sub):
        if not m:
            return
        r = _safe(lambda: (up_q().count(), total_q().count()), None)
        if r is not None:
            up, total = r
            tiles.append({"label": label, "value": f"{up}/{total}", "sub": sub, "icon": icon,
                          "tile": "s-ok" if up == total else "s-warn", "href": href})

    UrlCheck, Domain = model("urlchecker", "UrlCheck"), model("domainmonitor", "Domain")
    Device, TcpCheck = model("network", "Device"), model("tcpcheck", "TcpCheck")
    ratio("URLs online", UrlCheck, lambda: _scoped(UrlCheck, user).filter(enabled=True, last_status="online"),
          lambda: _scoped(UrlCheck, user).filter(enabled=True), "link", _url("urlchecker:index"), "Enabled checks")
    ratio("Domains up", Domain, lambda: _scoped(Domain, user, "site_key").filter(is_active=True, status="up"),
          lambda: _scoped(Domain, user, "site_key").filter(is_active=True), "globe", _url("domains:overview"),
          "Active domains")
    if Device:
        ratio("Devices up", Device, lambda: _scoped(Device, user).filter(enabled=True, status="up"),
              lambda: _scoped(Device, user).filter(enabled=True), "network", _url("network:all"), "Monitored devices")
    if TcpCheck:
        ratio("TCP online", TcpCheck, lambda: _scoped(TcpCheck, user).filter(enabled=True, last_status="online"),
              lambda: _scoped(TcpCheck, user).filter(enabled=True), "plug", _url("tcpcheck:index"), "Enabled checks")
    return tiles


def recent_events(user, limit=10):
    Event = model("core", "Event")
    return _safe(lambda: list(_scoped(Event, user).exclude(severity="info").order_by("-occurred_at")[:limit]), [])


# ------------------------------------------------------------------ site picker
def site_names(user=None):
    """Site records plus any site name used by monitored objects (minus 'All Sites'), limited to the user's sites."""
    names = set()
    Site = model("core", "Site")
    if Site:
        names |= set(_safe(lambda: list(_tenant(Site.objects.all()).values_list("name", flat=True)), []))
    for app_label, name, field in (("urlchecker", "UrlCheck", "site"), ("domainmonitor", "Domain", "site_key"),
                                   ("network", "Device", "site"), ("tcpcheck", "TcpCheck", "site")):
        m = model(app_label, name)
        if m:
            names |= set(_safe(lambda: list(_tenant(m.objects.all()).values_list(field, flat=True).distinct()), []))
    names -= {"", "All Sites", None}
    allowed = visible_sites(user) if user is not None else None
    if allowed is not None:
        names &= allowed
    return sorted(names)
