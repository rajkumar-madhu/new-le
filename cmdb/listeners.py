"""Event listeners: when a monitored URL check or domain linked to CIs goes down, record which
configuration items are impacted (an informational "impact" event; no notification)."""
import logging

from django.dispatch import receiver

from core.events import emit, event_emitted

log = logging.getLogger("linkedeye.cmdb")

WATCHED = {"urlchecker.urlcheck": "url_checks", "domainmonitor.domain": "domains"}


def impact_for_event(event):
    """Emit a cmdb impact event for a critical urlchecker/domainmonitor event. Returns the event or None."""
    if event.source == "cmdb" or event.severity != "critical":
        return None
    rel = WATCHED.get(event.object_type)
    if not rel or not str(event.object_id).isdigit():
        return None
    from . import services
    from .models import ConfigurationItem
    direct = list(ConfigurationItem.objects.filter(tenant_key=services.tenant(), **{f"{rel}__pk": int(event.object_id)})
                  .exclude(status="retired"))
    if not direct:
        return None
    edges = services.edges_for()
    affected = {c.pk: c for c in direct}
    for c in direct:
        for row in services.impacted(c, edges=edges):
            affected.setdefault(row["ci"].pk, row["ci"])
    names = sorted((c.name for c in affected.values()), key=str.lower)
    shown = ", ".join(names[:12]) + (f" and {len(names) - 12} more" if len(names) > 12 else "")
    return emit("cmdb", f"{len(names)} configuration item(s) impacted: {event.title}"[:200], severity="info", kind="impact",
                message=f"Directly linked: {', '.join(c.name for c in direct)}. Impacted: {shown}.", site=event.site,
                object_type=event.object_type, object_id=event.object_id,
                fingerprint=f"cmdb:impact:{event.object_type}:{event.object_id}", cis=names[:100], cause=event.title)


@receiver(event_emitted, dispatch_uid="cmdb.on_event")
def on_event(sender, event, **kwargs):
    try:
        impact_for_event(event)
    except Exception:  # noqa: BLE001 - listeners must never raise
        log.exception("cmdb impact listener failed for %s", event)
