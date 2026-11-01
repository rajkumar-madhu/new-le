"""Unified event stream. Modules call emit(); listeners (Service Desk auto-incidents,
notifications) subscribe to the `event_emitted` signal."""
import logging

from django.dispatch import Signal

from .models import Event

log = logging.getLogger("linkedeye.events")

# sent with sender=Event, event=<Event>
event_emitted = Signal()


def emit(source, title, severity="info", message="", kind="state_change", site="", obj=None,
         object_type="", object_id="", fingerprint="", **data):
    ev = Event.objects.create(
        source=source, title=title[:200], severity=severity, message=message, kind=kind, site=site or "",
        object_type=object_type or (obj._meta.label_lower if obj is not None else ""),
        object_id=str(object_id or getattr(obj, "pk", "") or ""),
        fingerprint=fingerprint[:200], data=data,
    )
    try:
        event_emitted.send(sender=Event, event=ev)
    except Exception:  # a broken listener must never break the emitter (e.g. the probe loop)
        log.exception("event listener failed for %s", ev)
    return ev
