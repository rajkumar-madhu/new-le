"""Audit helper: audit(request, "create", obj, field=value…)."""
from .models import AuditEvent


def _ip(request):
    if request is None:
        return None
    fwd = request.META.get("HTTP_X_FORWARDED_FOR", "")
    return (fwd.split(",")[0].strip() or request.META.get("REMOTE_ADDR")) or None


def audit(request, action, obj=None, object_type=None, result="ok", **details):
    user = getattr(request, "user", None) if request is not None else None
    return AuditEvent.objects.create(
        actor=user if user is not None and user.is_authenticated else None,
        actor_name=(user.get_username() if user is not None and user.is_authenticated else "system"),
        action=action,
        object_type=object_type or (obj._meta.label_lower if obj is not None else ""),
        object_id=str(getattr(obj, "pk", "") or ""),
        object_repr=str(obj)[:200] if obj is not None else "",
        result=result,
        source_ip=_ip(request),
        details={k: (v if isinstance(v, (str, int, float, bool, type(None), list, dict)) else str(v)) for k, v in details.items()},
    )
