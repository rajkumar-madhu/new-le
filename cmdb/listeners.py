"""Event listeners: when a monitored URL check or domain linked to CIs goes down, record which
configuration items are impacted (an informational "impact" event; no notification)."""
import logging

from django.dispatch import receiver

from core.events import emit, event_emitted

log = logging.getLogger("linkedeye.cmdb")

WATCHED = {"urlchecker.urlcheck": "url_checks", "domainmonitor.domain": "domains"}


GLOBAL_SITES = ("All Sites", "")


def impact_for_event(event):
    """Emit cmdb impact events for a critical urlchecker/domainmonitor event. Returns the event emitted for the
    source event's site (or the first one), or None.

    Events are visible per site, so one event is emitted per site of the impacted CIs and names only that site's
    CIs (plus "All Sites" ones): viewers of one site never learn the names of items on sites they cannot see.
    """
    if event.source == "cmdb" or event.severity != "critical":
        return None
    rel = WATCHED.get(event.object_type)
    from . import services
    pk = services.as_pk(event.object_id)
    if not rel or pk is None:
        return None
    from .models import ConfigurationItem
    direct = list(ConfigurationItem.objects.filter(tenant_key=services.tenant(), **{f"{rel}__pk": pk})
                  .exclude(status="retired"))
    if not direct:
        return None
    edges = services.edges_for()
    affected = {c.pk: c for c in direct}
    for c in direct:
        for row in services.impacted(c, edges=edges):
            affected.setdefault(row["ci"].pk, row["ci"])
    shared = [c for c in affected.values() if (c.site or "") in GLOBAL_SITES]
    by_site = {}
    for c in affected.values():
        if (c.site or "") not in GLOBAL_SITES:
            by_site.setdefault(c.site, []).append(c)
    groups = dict(sorted(by_site.items()))
    if shared and (event.site or "") not in groups:
        groups = {event.site or "": [], **groups}
    base_fp = f"cmdb:impact:{event.object_type}:{event.object_id}"
    out = []
    for site, cis in groups.items():
        visible = {c.pk for c in cis} | {c.pk for c in shared}
        names = sorted((c.name for c in affected.values() if c.pk in visible), key=str.lower)
        linked = [c.name for c in direct if c.pk in visible] or ["none on this site"]
        shown = ", ".join(names[:12]) + (f" and {len(names) - 12} more" if len(names) > 12 else "")
        # the failed check or domain is on the source site: viewers of other sites do not learn its name either
        cause = (event.title if (event.site or "") in GLOBAL_SITES or site == (event.site or "")
                 else "a critical event on another site")
        out.append(emit("cmdb", f"{len(names)} configuration item(s) impacted: {cause}"[:200], severity="info",
                        kind="impact", message=f"Directly linked: {', '.join(linked)}. Impacted: {shown}.", site=site,
                        object_type=event.object_type, object_id=event.object_id,
                        fingerprint=base_fp if site == (event.site or "") else f"{base_fp}:{site}",
                        cis=names[:100], cause=cause))
    return next((e for e in out if e.site == (event.site or "")), out[0] if out else None)


@receiver(event_emitted, dispatch_uid="cmdb.on_event")
def on_event(sender, event, **kwargs):
    try:
        impact_for_event(event)
    except Exception:  # noqa: BLE001 - listeners must never raise
        log.exception("cmdb impact listener failed for %s", event)
