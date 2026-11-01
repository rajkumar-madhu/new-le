"""POST /api/v1/alertmanager/ – Alertmanager webhook receiver (payload version 4).

Authentication: `Authorization: Bearer <settings.ALERTMANAGER_WEBHOOK_TOKEN>` (constant-time compare).
The endpoint is disabled (503) while the token is unset. Bodies over 1 MB are refused (413).
"""
import hmac
import logging

from django.conf import settings
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from core.audit import audit

from .. import alerts as svc

log = logging.getLogger("linkedeye.telemetry")


def _deny(status, error, **extra):
    resp = JsonResponse({"error": error, **extra}, status=status)
    if status == 401:
        resp["WWW-Authenticate"] = 'Bearer realm="linkedeye-alertmanager"'
    return resp


def _authorized(request, token):
    header = request.META.get("HTTP_AUTHORIZATION", "")
    scheme, _, supplied = header.partition(" ")
    if scheme.lower() != "bearer":
        supplied = ""
    # compare as bytes so non-ASCII input cannot raise, and always run the comparison
    return hmac.compare_digest(supplied.strip().encode("utf-8", "surrogatepass"), token.encode("utf-8"))


def _read_body(request):
    """Body bytes, or None when it exceeds MAX_BODY_BYTES (checked before and while reading)."""
    try:
        declared = int(request.META.get("CONTENT_LENGTH") or 0)
    except ValueError:
        declared = 0
    if declared > svc.MAX_BODY_BYTES:
        return None
    data = request.read(svc.MAX_BODY_BYTES + 1)
    if len(data) > svc.MAX_BODY_BYTES:
        return None
    return data


@csrf_exempt
def alertmanager_webhook(request):
    if request.method != "POST":
        resp = _deny(405, "method not allowed; Alertmanager must POST")
        resp["Allow"] = "POST"
        return resp
    token = getattr(settings, "ALERTMANAGER_WEBHOOK_TOKEN", "") or ""
    if not token:
        return _deny(503, "webhook disabled: set LINKEDEYE_ALERTMANAGER_WEBHOOK_TOKEN on the LinkedEye server")
    if not _authorized(request, token):
        log.warning("alertmanager webhook: rejected request from %s (bad or missing bearer token)", request.META.get("REMOTE_ADDR"))
        return _deny(401, "invalid or missing bearer token")
    raw = _read_body(request)
    if raw is None:
        return _deny(413, f"payload larger than {svc.MAX_BODY_BYTES // 1024} KB")
    try:
        payload, alerts = svc.parse_payload(raw)
    except svc.PayloadError as e:
        return _deny(400, str(e))
    stats = svc.ingest(payload, alerts)
    audit(request, "ingest", object_type="telemetry.alert", receiver=str(payload.get("receiver", ""))[:200],
          group_key=str(payload.get("groupKey", ""))[:200], status=str(payload.get("status", ""))[:20], **stats)
    return JsonResponse({"status": "ok", **stats})
