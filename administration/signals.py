"""Sign-in auditing: successful and failed interactive sign-ins become AuditEvent rows (actions `login`,
`login_failed`, `logout`).

Only sign-ins that arrive through an HTTP request (REMOTE_ADDR set) are recorded; programmatic logins such as the
test client's force_login() carry no client address and are skipped. Listeners never raise."""
import logging

from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver

log = logging.getLogger("linkedeye.administration")


def _interactive(request):
    return request is not None and bool(getattr(request, "META", {}).get("REMOTE_ADDR"))


@receiver(user_logged_in, dispatch_uid="administration.audit_login")
def audit_login(sender, request, user, **kwargs):
    if not _interactive(request):
        return
    try:
        from core.audit import audit
        audit(request, "login", user)
    except Exception:
        log.exception("could not audit sign-in")


@receiver(user_logged_out, dispatch_uid="administration.audit_logout")
def audit_logout(sender, request, user, **kwargs):
    if not _interactive(request) or user is None:
        return
    try:
        from core.audit import audit
        audit(request, "logout", user)
    except Exception:
        log.exception("could not audit sign-out")


@receiver(user_login_failed, dispatch_uid="administration.audit_login_failed")
def audit_login_failed(sender, credentials, request=None, **kwargs):
    if not _interactive(request):
        return
    try:
        from core.audit import audit
        username = str((credentials or {}).get("username", ""))[:150]
        audit(request, "login_failed", object_type="auth.user", result="failed", username=username)
    except Exception:
        log.exception("could not audit failed sign-in")
