"""CMDB services: lookups, link health, dependency graph and impact analysis.

Public cross-module interface (docs/MODULES.md): ``find_ci(name)``.
"""
from collections import defaultdict, deque

from django.apps import apps
from django.conf import settings
from django.db import DatabaseError
from django.db.models import Q
from django.urls import NoReverseMatch, reverse

from .models import IMPACT_FORWARD, IMPACT_REVERSE, CIType, ConfigurationItem, Relationship, RelType

SEVERITY = {"critical": 3, "warning": 2, "healthy": 1, "unknown": 0}
STATE_CLASS = {"critical": "crit", "warning": "warn", "healthy": "ok", "unknown": "unk"}


def tenant():
    return settings.LINKEDEYE_TENANT


def ci_queryset(user=None):
    """CIs of the current tenant, scoped to the user's sites when a user is given."""
    qs = ConfigurationItem.objects.filter(tenant_key=tenant())
    if user is not None:
        from core.access import scope_by_site
        qs = scope_by_site(qs, user, field="site")
    return qs


def find_ci(name, tenant_key=None):
    """Return the CI called `name` (case-insensitive) in the tenant, or None."""
    name = (name or "").strip()
    if not name:
        return None
    qs = ConfigurationItem.objects.filter(tenant_key=tenant_key or tenant())
    return qs.filter(name=name).first() or qs.filter(name__iexact=name).first()


def worst(states):
    """Worst health of an iterable of states; unknown only when nothing is known."""
    states = [s for s in states if s]
    if not states:
        return "unknown"
    return max(states, key=lambda s: SEVERITY.get(s, 0))


# ----------------------------------------------------------------------------- link health
URL_STATE = {"online": "healthy", "degraded": "warning", "down": "critical"}
DOMAIN_STATE = {"up": "healthy", "down": "critical"}


def check_rows(ci):
    """Linked URL checks and domains of one CI with their latest status (for the detail page)."""
    rows = []
    for c in ci.url_checks.all():
        state = URL_STATE.get(c.last_status, "unknown") if c.enabled else "unknown"
        rows.append({"kind": "URL check", "name": c.name, "target": c.url, "status": c.last_status if c.enabled else "paused",
                     "state": state, "response_ms": c.last_response_ms, "checked": c.last_checked_at,
                     "message": c.last_error, "url": _safe_reverse("urlchecker:detail", c.pk)})
    for d in ci.domains.all():
        active = d.is_active and d.monitor_enabled
        state = DOMAIN_STATE.get(d.status, "unknown") if active else "unknown"
        if state == "healthy" and d.ssl_status in ("Expiring",):
            state = "warning"
        if state == "healthy" and d.ssl_status in ("Expired", "Invalid"):
            state = "critical"
        rows.append({"kind": "Domain", "name": d.hostname, "target": f"https://{d.hostname}/",
                     "status": d.status if active else "paused", "state": state, "response_ms": d.response_ms,
                     "checked": d.last_checked_at, "message": d.last_error, "ssl": d.ssl_status,
                     "url": _safe_reverse("domains:list") + f"?selected={d.pk}" if _safe_reverse("domains:list") else ""})
    return rows


def link_health(cis):
    """{ci_pk: healthy|warning|critical|unknown} from the latest status of linked checks and domains."""
    cis = list(cis)
    ids = [c.pk for c in cis]
    out = {pk: [] for pk in ids}
    if not ids:
        return {}
    Through = ConfigurationItem.url_checks.through
    for ci_id, status, enabled in Through.objects.filter(configurationitem_id__in=ids).values_list(
            "configurationitem_id", "urlcheck__last_status", "urlcheck__enabled"):
        if enabled:
            out[ci_id].append(URL_STATE.get(status))
    DThrough = ConfigurationItem.domains.through
    for ci_id, status, active, mon, ssl in DThrough.objects.filter(configurationitem_id__in=ids).values_list(
            "configurationitem_id", "domain__status", "domain__is_active", "domain__monitor_enabled", "domain__ssl_status"):
        if active and mon:
            s = DOMAIN_STATE.get(status)
            if s == "healthy" and ssl == "Expiring":
                s = "warning"
            elif s == "healthy" and ssl in ("Expired", "Invalid"):
                s = "critical"
            out[ci_id].append(s)
    return {pk: worst(v) for pk, v in out.items()}


# ----------------------------------------------------------------------------- graph
def edges_for(tenant_key=None):
    """All relationships of the tenant as tuples (pk, source_id, target_id, rel_type)."""
    return list(Relationship.objects.filter(source__tenant_key=tenant_key or tenant())
                .values_list("pk", "source_id", "target_id", "rel_type"))


def impact_adjacency(edges):
    """failed CI id -> [(impacted CI id, rel_type, direction)] along dependency relationships."""
    adj = defaultdict(list)
    for _pk, s, t, rt in edges:
        if rt in IMPACT_REVERSE:
            adj[t].append((s, rt, "in"))
        elif rt in IMPACT_FORWARD:
            adj[s].append((t, rt, "out"))
    return adj


def dependency_adjacency(edges):
    """CI id -> [(CI id it needs, rel_type)]: the reverse view of impact (what this CI relies on)."""
    adj = defaultdict(list)
    for _pk, s, t, rt in edges:
        if rt in IMPACT_REVERSE:
            adj[s].append((t, rt))
        elif rt in IMPACT_FORWARD:
            adj[t].append((s, rt))
    return adj


def impacted(ci, edges=None, max_nodes=500):
    """Every CI that transitively depends on `ci` (breadth first).

    Returns a list of dicts {ci, depth, via (rel label), parent (CI)} ordered by depth then name.
    """
    edges = edges if edges is not None else edges_for(ci.tenant_key)
    adj = impact_adjacency(edges)
    seen = {ci.pk: (0, None, None)}
    q = deque([ci.pk])
    while q and len(seen) <= max_nodes:
        cur = q.popleft()
        depth = seen[cur][0]
        for nxt, rt, _d in adj.get(cur, ()):
            if nxt not in seen:
                seen[nxt] = (depth + 1, rt, cur)
                q.append(nxt)
    seen.pop(ci.pk)
    objs = ConfigurationItem.objects.in_bulk(list(seen) + [p for _d, _r, p in seen.values() if p])
    objs[ci.pk] = ci
    labels = dict(RelType.choices)
    rows = []
    for pk, (d, rt, p) in seen.items():
        if pk not in objs:
            continue
        parent = objs.get(p)
        label = labels.get(rt, rt)
        # "A depends on B" (impact flows B -> A) reads "depends on B"; "B part of A" reads "contains B"
        via_text = f"contains {parent}" if rt in IMPACT_FORWARD else f"{label.lower()} {parent}"
        rows.append({"ci": objs[pk], "depth": d, "via": label, "via_text": via_text, "parent": parent})
    rows.sort(key=lambda r: (r["depth"], r["ci"].name.lower()))
    return rows


def dependencies(ci, edges=None, max_nodes=500):
    """Every CI that `ci` transitively relies on (the opposite direction of impact)."""
    edges = edges if edges is not None else edges_for(ci.tenant_key)
    adj = dependency_adjacency(edges)
    seen = {ci.pk: 0}
    q = deque([ci.pk])
    while q and len(seen) <= max_nodes:
        cur = q.popleft()
        for nxt, _rt in adj.get(cur, ()):
            if nxt not in seen:
                seen[nxt] = seen[cur] + 1
                q.append(nxt)
    seen.pop(ci.pk)
    objs = ConfigurationItem.objects.in_bulk(list(seen))
    return sorted(((objs[pk], d) for pk, d in seen.items() if pk in objs), key=lambda t: (t[1], t[0].name.lower()))


def would_cycle(source, target, rel_type, edges=None):
    """True when adding source -[rel_type]-> target closes a dependency loop."""
    if rel_type not in IMPACT_REVERSE and rel_type not in IMPACT_FORWARD:
        return False
    edges = edges if edges is not None else edges_for(source.tenant_key)
    adj = dependency_adjacency(edges)
    needer, needed = (source.pk, target.pk) if rel_type in IMPACT_REVERSE else (target.pk, source.pk)
    # loop if `needed` already (transitively) needs `needer`
    seen, q = {needed}, deque([needed])
    while q:
        cur = q.popleft()
        if cur == needer:
            return True
        for nxt, _rt in adj.get(cur, ()):
            if nxt not in seen:
                seen.add(nxt)
                q.append(nxt)
    return False


def domain_names(user=None):
    """Business domains: names of business_domain CIs plus free-text business_domain values."""
    qs = ci_queryset(user).exclude(status="retired")
    names = {n for n in qs.filter(ci_type=CIType.BUSINESS_DOMAIN).values_list("name", flat=True)}
    lower = {n.lower() for n in names}
    for n in qs.exclude(business_domain="").values_list("business_domain", flat=True).distinct():
        if n.lower() not in lower:
            names.add(n)
            lower.add(n.lower())
    return sorted(names, key=str.lower)


def domain_members(domain_name, user=None, types=None, cis=None, edges=None):
    """CIs that belong to a business domain: business_domain text match, or `part_of` the domain CI."""
    qs = cis if cis is not None else list(ci_queryset(user).exclude(status="retired"))
    key = domain_name.lower()
    dom_ci = next((c for c in qs if c.ci_type == CIType.BUSINESS_DOMAIN and c.name.lower() == key), None)
    part_of = set()
    if dom_ci is not None:
        edges = edges if edges is not None else edges_for()
        part_of = {s for _pk, s, t, rt in edges if t == dom_ci.pk and rt == RelType.PART_OF}
    out = [c for c in qs if c.ci_type != CIType.BUSINESS_DOMAIN and (c.business_domain.lower() == key or c.pk in part_of)]
    if types:
        out = [c for c in out if c.ci_type in types]
    return dom_ci, out


# ----------------------------------------------------------------------------- servicedesk (optional)
def _safe_reverse(name, *args):
    try:
        return reverse(name, args=args or None)
    except NoReverseMatch:
        return ""


def recent_incidents(ci_names, limit=5, fingerprints=()):
    """Recent incidents raised against any of `ci_names` (or carrying one of `fingerprints`, e.g. the
    ``url:<pk>`` fingerprint of a linked URL check) via the Service Desk module.

    Returns None when Service Desk is not installed / not migrated (callers show "not connected").
    """
    try:
        Ticket = apps.get_model("servicedesk", "Ticket")
    except LookupError:
        return None
    fields = {f.name for f in Ticket._meta.get_fields()}
    if "ci_name" not in fields:
        return None
    names = [n for n in ci_names if n]
    fps = [f for f in fingerprints if f] if "fingerprint" in fields else []
    if not names and not fps:
        return {"items": [], "open": 0}
    try:
        cond = Q(ci_name__in=names)
        if fps:
            cond |= Q(fingerprint__in=fps)
        qs = Ticket.objects.filter(cond)
        if "tenant_key" in fields:
            qs = qs.filter(tenant_key=tenant())
        if "kind" in fields:
            qs = qs.filter(kind="incident")
        order = "-opened_at" if "opened_at" in fields else ("-created_at" if "created_at" in fields else "-pk")
        items = list(qs.order_by(order)[:limit])
        if hasattr(qs, "open"):
            open_count = qs.open().count()
        elif "status" in fields:
            open_count = qs.exclude(status__in=["resolved", "closed", "cancelled", "rejected"]).count()
        else:
            open_count = len(items)
    except (DatabaseError, ValueError, TypeError):
        return None
    out = []
    for t in items:
        url = ""
        if hasattr(t, "get_absolute_url"):
            try:
                url = t.get_absolute_url()
            except Exception:  # noqa: BLE001 - another module's model; never break the page
                url = ""
        out.append({
            "number": getattr(t, "number", "") or f"#{t.pk}",
            "priority": str(getattr(t, "priority", "") or ""),
            "title": getattr(t, "title", "") or getattr(t, "subject", "") or str(t),
            "status": str(getattr(t, "status", "") or ""),
            "created": getattr(t, "opened_at", None) or getattr(t, "created_at", None),
            "ci_name": getattr(t, "ci_name", ""),
            "url": url or _safe_reverse("servicedesk:incidents"),
        })
    return {"items": out, "open": open_count, "list_url": _safe_reverse("servicedesk:incidents")}


def ci_fingerprints(cis):
    """Event fingerprints of the URL checks and domains linked to `cis` (to find incidents raised from them)."""
    out = []
    for c in cis:
        out += [f"url:{u.pk}" for u in c.url_checks.all()]
        out += [f"domain:{d.pk}" for d in c.domains.all()]
    return out


# ----------------------------------------------------------------------------- permissions
def can_manage(user, perm, site):
    """`perm` on the CI's site. Global ("All Sites") records need the role on every site."""
    from core.access import can, visible_sites
    if user is None:
        return False
    if not site or site == "All Sites":
        return can(user, perm) and visible_sites(user) is None
    return can(user, perm, site)
