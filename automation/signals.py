"""Event workflows: every emitted event is evaluated against the enabled automation rules.

Events from the automation module itself are ignored (no loops), and so are events emitted while a rule's action
runs (e.g. the incident a rule opens). Listeners must never raise (core.events contract).
"""
import logging

from django.dispatch import receiver

from core.events import event_emitted

from . import services

log = logging.getLogger("linkedeye.automation")


@receiver(event_emitted, dispatch_uid="automation.on_event")
def on_event(sender, event, **kwargs):
    try:
        services.evaluate_event(event)
    except Exception:
        log.exception("automation rules failed for event %s", getattr(event, "pk", None))
