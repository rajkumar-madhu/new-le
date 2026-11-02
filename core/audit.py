"""Audit helper: audit(request, "create", obj, field=value…)."""
import ipaddress

from django.conf import settings

from .models import AuditEvent


def _addr(value):
    try:
        addr = ipaddress.ip_address((value or "").strip())
    except ValueError:
        return None
    if addr.version == 6:
        if addr.ipv4_mapped:  # dual-stack peer "::ffff:10.0.0.5" must match an IPv4 trusted proxy
            return addr.ipv4_mapped
        if addr.scope_id:  # "::1%<anything>" would reach inet / char(39) unchanged and fail the insert
            return ipaddress.IPv6Address(int(addr))
    return addr


def _trusted_proxies():
    nets = []
    for item in getattr(settings, "TRUSTED_PROXIES", []):
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            continue
    return nets


def _ip(request):
    """The peer address (REMOTE_ADDR). X-Forwarded-For is believed only when the peer is a trusted proxy
    (settings.TRUSTED_PROXIES); then the right-most hop that is not a trusted proxy is the client, because
    proxies append to whatever the client sent. Anything that is not an IP address is stored as None."""
    if request is None:
        return None
    peer = _addr(request.META.get("REMOTE_ADDR"))
    if peer is None:
        return None
    trusted = _trusted_proxies()
    fwd = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if not fwd.strip() or not any(peer in net for net in trusted):
        return str(peer)
    hop = peer
    for raw in reversed(fwd.split(",")):
        hop = _addr(raw)
        if hop is None:
            return None
        if not any(hop in net for net in trusted):
            break
    return str(hop)


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
