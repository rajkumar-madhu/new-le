"""Turns critical events from other modules into incidents and recoveries into mitigation.

* critical event (source != servicedesk, INCIDENT_AUTO_CREATE on) -> open_incident (deduped by fingerprint):
  P1 when event.data["priority"] == "P1", otherwise P2.
* ok event whose fingerprint matches an open incident -> 'Recovered' timeline note + move to Mitigated.
Listeners must never raise (core.events contract).
"""
import logging

from django.conf import settings
from django.db import transaction
from django.dispatch import receiver

from core.events import event_emitted

from . import services
from . import workflow as wf

log = logging.getLogger("linkedeye.servicedesk")

# incident states that a recovery moves forward to Mitigated
MITIGATABLE = {"new", "acknowledged", "investigating"}


def fingerprint_for(event):
    return (event.fingerprint or f"evt:{event.title}")[:200]


def handle_event(event):
    if event.source == "servicedesk":
        return None
    data = event.data if isinstance(event.data, dict) else {}
    if event.severity == "critical":
        if not getattr(settings, "INCIDENT_AUTO_CREATE", False):
            return None
        priority = "P1" if str(data.get("priority", "")).upper() == "P1" else "P2"
        desc = event.message or ""
        desc += ("\n\n" if desc else "") + f"Raised automatically from a critical {event.source} event at {event.occurred_at:%Y-%m-%d %H:%M:%S %Z}."
        return services.open_incident(
            title=event.title, description=desc, priority=priority, site=event.site, source=event.source,
            fingerprint=fingerprint_for(event), ci_name=str(data.get("ci") or data.get("ci_name") or data.get("host") or "")[:200],
            category=str(data.get("category") or "")[:80], client=str(data.get("client") or "")[:100])
    if event.severity == "ok":
        from .models import Ticket
        fp = fingerprint_for(event)
        touched = []
        for t in Ticket.objects.for_tenant().open().filter(kind="incident", fingerprint=fp):
            services._note(t, "system", f"Recovered: {event.title}" + (f"\n{event.message}" if event.message else ""),
                           author_name=event.source)
            if t.status in MITIGATABLE:
                if not wf.allowed("incident", t.status, "mitigated"):
                    services.transition(t, "acknowledged", user=None, note="Acknowledged automatically on recovery.",
                                        actor_name=event.source)
                services.transition(t, "mitigated", user=None, note="Monitoring reports the service recovered.",
                                    actor_name=event.source)
            touched.append(t)
        return touched or None
    return None


@receiver(event_emitted, dispatch_uid="servicedesk.on_event")
def on_event(sender, event, **kwargs):
    try:
        # savepoint: if anything here fails, only our writes roll back and the emitter's transaction stays usable
        with transaction.atomic():
            handle_event(event)
    except Exception:
        log.exception("service desk could not process event %s", getattr(event, "pk", None))
