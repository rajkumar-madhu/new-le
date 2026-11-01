"""Outbound notifications for critical/warning events: generic JSON webhooks
(Slack/Teams/StackStorm/Apprise-compatible endpoints) and e-mail."""
import json
import logging
import urllib.request

from django.conf import settings
from django.core.mail import send_mail
from django.dispatch import receiver

from .events import event_emitted

log = logging.getLogger("linkedeye.notify")


def _post(url, payload, timeout=5):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - URLs come from operator settings
        return r.status


def deliver(event):
    if event.severity not in settings.NOTIFY_SEVERITIES:
        return 0
    payload = {"title": event.title, "body": event.message, "severity": event.severity, "source": event.source,
               "site": event.site, "occurred_at": event.occurred_at.isoformat(), "kind": event.kind,
               "object": f"{event.object_type}:{event.object_id}"}
    sent = 0
    for url in settings.NOTIFY_WEBHOOK_URLS:
        try:
            _post(url, payload)
            sent += 1
        except Exception as e:  # never let a notification failure break the caller
            log.warning("webhook %s failed: %s", url.split("?")[0], e)
    if settings.NOTIFY_EMAILS:
        try:
            send_mail(f"[LinkedEye {event.severity.upper()}] {event.title}", event.message or event.title,
                      settings.DEFAULT_FROM_EMAIL, settings.NOTIFY_EMAILS, fail_silently=False)
            sent += 1
        except Exception as e:
            log.warning("email notification failed: %s", e)
    return sent


@receiver(event_emitted)
def _on_event(sender, event, **kwargs):
    if settings.NOTIFY_WEBHOOK_URLS or settings.NOTIFY_EMAILS:
        deliver(event)
