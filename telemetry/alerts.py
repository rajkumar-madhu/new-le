"""Alertmanager webhook ingestion (payload version 4) and alert state changes.

Each alert is upserted by fingerprint. Core events are emitted only on state changes, so Alertmanager's
repeat notifications do not flood the event stream:

  new / re-fired / severity changed while firing -> severity "critical" (critical, page), "warning" (warning)
                                                     or "info" (anything else)
  firing -> resolved                               -> "ok"

Event fingerprints are "am:<fingerprint>", so Service Desk opens one incident per alert and moves it to
Mitigated when the alert resolves.
"""
import hashlib
import json
import logging
from datetime import timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from core.events import emit

from .fmt import parse_ts
from .models import Alert

log = logging.getLogger("linkedeye.telemetry")

MAX_BODY_BYTES = 1024 * 1024
MAX_ALERTS = 1000
CRITICAL_SEVERITIES = {"critical", "page"}
WARNING_SEVERITIES = {"warning"}


class PayloadError(ValueError):
    pass


def event_severity(status, severity):
    if status == Alert.RESOLVED:
        return "ok"
    s = (severity or "").lower()
    if s in CRITICAL_SEVERITIES:
        return "critical"
    if s in WARNING_SEVERITIES:
        return "warning"
    return "info"


def _clip(value, n):
    return str(value if value is not None else "")[:n]


def _str_map(d):
    """Alertmanager sends string->string maps; coerce anything else defensively."""
    if not isinstance(d, dict):
        return {}
    return {str(k)[:200]: _clip(v, 4000) for k, v in list(d.items())[:200]}


def fingerprint_of(alert, labels):
    fp = alert.get("fingerprint")
    if isinstance(fp, str) and fp.strip():
        return fp.strip()[:64]
    # Alertmanager < 0.19 did not send fingerprints: derive a stable one from the label set
    return hashlib.sha256(json.dumps(labels, sort_keys=True).encode()).hexdigest()[:16]


def parse_payload(raw):
    """bytes -> (payload dict, [alert dicts]). Raises PayloadError."""
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise PayloadError("body is not valid JSON") from None
    if not isinstance(payload, dict):
        raise PayloadError("payload must be a JSON object")
    version = payload.get("version")
    if version is not None and str(version) != "4":
        raise PayloadError(f"unsupported webhook version {version!r} (expected \"4\")")
    alerts = payload.get("alerts")
    if not isinstance(alerts, list):
        raise PayloadError("'alerts' must be a list")
    if len(alerts) > MAX_ALERTS:
        raise PayloadError(f"too many alerts in one notification (limit {MAX_ALERTS})")
    for a in alerts:
        if not isinstance(a, dict):
            raise PayloadError("each alert must be an object")
        if a.get("status", "firing") not in (Alert.FIRING, Alert.RESOLVED):
            raise PayloadError(f"unknown alert status {a.get('status')!r}")
    return payload, alerts


def _cmdb_ci(instance):
    if not instance:
        return None
    from .hosts import cmdb_map
    return cmdb_map([instance]).get(instance)


def _event_title(a):
    where = f" on {a.instance}" if a.instance else ""
    if a.status == Alert.RESOLVED:
        return f"Resolved: {a.alertname}{where}"
    return f"{a.alertname}{where}" + (f" – {a.summary}" if a.summary else "")


def emit_for(a, severity, reason):
    data = {"alertname": a.alertname, "severity_label": a.severity, "instance": a.instance, "job": a.job,
            "status": a.status, "reason": reason, "labels": a.labels, "category": "Monitoring"}
    if (a.severity or "").lower() == "page":
        data["priority"] = "P1"
    ci = _cmdb_ci(a.instance)
    data["host"] = ci.name if ci is not None else (a.instance.rsplit(":", 1)[0] if a.instance.count(":") == 1 else a.instance)
    msg = "\n".join(x for x in (a.summary, a.description) if x)
    return emit(source="telemetry", title=_event_title(a), severity=severity, message=msg, kind="alert",
                site=a.site, obj=a, fingerprint=a.event_fingerprint, **data)


def ingest(payload, alerts, now=None):
    """Upsert every alert; returns counts {received, created, updated, events}."""
    now = now or timezone.now()
    receiver = _clip(payload.get("receiver"), 200)
    stats = {"received": len(alerts), "created": 0, "updated": 0, "events": 0}
    for raw in alerts:
        labels = _str_map(raw.get("labels"))
        annotations = _str_map(raw.get("annotations"))
        fp = fingerprint_of(raw, labels)
        status = raw.get("status") or Alert.FIRING
        severity = labels.get("severity", "")[:40]
        instance = labels.get("instance", "")[:255]
        fields = {
            "status": status, "alertname": (labels.get("alertname") or "unnamed")[:200], "severity": severity,
            "instance": instance, "job": labels.get("job", "")[:200], "labels": labels, "annotations": annotations,
            "summary": (annotations.get("summary") or annotations.get("message") or annotations.get("title") or "")[:500],
            "description": annotations.get("description", ""),
            "receiver": receiver, "generator_url": _clip(raw.get("generatorURL"), 1000),
            "starts_at": parse_ts(raw.get("startsAt")),
            "ends_at": parse_ts(raw.get("endsAt")) if status == Alert.RESOLVED else None,
            "last_received_at": now,
        }
        if status == Alert.RESOLVED and fields["ends_at"] is None:
            fields["ends_at"] = now
        site = labels.get("site", "")[:100]
        reason = None
        with transaction.atomic():
            a = Alert.objects.select_for_update().filter(fingerprint=fp).first()
            if a is None:
                if not site:
                    ci = _cmdb_ci(instance)
                    site = (getattr(ci, "site", "") or "")[:100]
                a = Alert(fingerprint=fp, tenant_key=settings.LINKEDEYE_TENANT, site=site, receive_count=0,
                          fire_count=0, **fields)
                stats["created"] += 1
                reason = "new" if status == Alert.FIRING else None
            else:
                prev_status, prev_sev = a.status, (a.severity or "").lower()
                if prev_status == Alert.RESOLVED and status == Alert.FIRING:
                    reason = "refired"
                    a.acknowledged_at = None
                    a.acknowledged_by = None
                elif prev_status == Alert.FIRING and status == Alert.RESOLVED:
                    reason = "resolved"
                elif status == Alert.FIRING and prev_sev != severity.lower():
                    reason = "severity"
                for k, v in fields.items():
                    setattr(a, k, v)
                if site:
                    a.site = site
                stats["updated"] += 1
            a.receive_count += 1
            if reason in ("new", "refired"):
                a.fire_count += 1
            a.save()
        if reason:
            emit_for(a, event_severity(a.status, a.severity), reason)
            stats["events"] += 1
    return stats


def acknowledge(alerts, user, now=None):
    """Mark alerts acknowledged; returns the ones that changed."""
    now = now or timezone.now()
    changed = []
    for a in alerts:
        if a.acknowledged_at is None:
            a.acknowledged_at = now
            a.acknowledged_by = user
            a.save(update_fields=["acknowledged_at", "acknowledged_by", "updated_at"])
            emit(source="telemetry", title=f"Acknowledged: {a.alertname}" + (f" on {a.instance}" if a.instance else ""),
                 severity="info", kind="ack", site=a.site, obj=a, fingerprint=a.event_fingerprint,
                 message=f"Acknowledged by {user.get_username()}", user=user.get_username())
            changed.append(a)
    return changed


def unacknowledge(alerts):
    changed = []
    for a in alerts:
        if a.acknowledged_at is not None:
            a.acknowledged_at = None
            a.acknowledged_by = None
            a.save(update_fields=["acknowledged_at", "acknowledged_by", "updated_at"])
            changed.append(a)
    return changed


def retention_days():
    return int(getattr(settings, "TELEMETRY_ALERT_RETENTION_DAYS", 90) or 90)


def prune(now=None):
    """Delete resolved alerts older than the retention window. Returns the number deleted."""
    now = now or timezone.now()
    cutoff = now - timedelta(days=retention_days())
    n, _ = Alert.objects.for_tenant().resolved().filter(last_received_at__lt=cutoff).delete()
    return n
