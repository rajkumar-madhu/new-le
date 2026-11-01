"""Automation services: StackStorm and webhook calls, event-rule evaluation and template application.

Cross-module interface (docs/MODULES.md):
    trigger_stackstorm(trigger, payload) -> Execution   (never raises)

Everything that talks to the network records an Execution row first and finishes it with the outcome, so the
StackStorm and Workflows pages show exactly what was sent and what came back.
"""
import http.client
import json
import logging
import re
import socket
import ssl
import threading
import urllib.error
import urllib.request
from datetime import timedelta
from urllib.parse import urlsplit

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.models import F
from django.utils import timezone

from core.access import PERMS, RANK, can, scope_by_site

from .models import Execution, Rule, Runbook, Template

log = logging.getLogger("linkedeye.automation")

ST2_TIMEOUT = 10
WEBHOOK_TIMEOUT = 10
EXCERPT_CHARS = 2000
MAX_RESPONSE = 64 * 1024
TRIGGER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-/]{0,199}$")
RETENTION_DAYS_DEFAULT = 90
STALE_PENDING_MINUTES = 15

_state = threading.local()


def tenant():
    return settings.LINKEDEYE_TENANT


def _name(user):
    if user is None or not getattr(user, "is_authenticated", False):
        return ""
    return user.get_username()


# ------------------------------------------------------------------ access helpers
def can_manage(user, perm, site):
    """`perm` on a record's site. Records for "All Sites" (or no site) need the permission tenant-wide."""
    if site and site != "All Sites":
        return can(user, perm, site_name=site)
    if not can(user, perm):
        return False
    if user.is_superuser:
        return True
    from core.models import Membership
    ms = list(Membership.objects.filter(user=user))
    if not ms:  # users without memberships hold their default role everywhere
        return True
    return any(m.site_id is None and RANK[m.role] >= PERMS[perm] for m in ms)


def runbooks_for(user):
    return scope_by_site(Runbook.objects.filter(tenant_key=tenant()), user)


def rules_for(user):
    return scope_by_site(Rule.objects.filter(tenant_key=tenant()), user)


def executions_for(user):
    return scope_by_site(Execution.objects.filter(tenant_key=tenant()), user)


def templates_for(user):
    return Template.objects.filter(tenant_key=tenant())


def template_site(template_or_values):
    """The site a template's records default to ("All Sites" when it names none)."""
    values = template_or_values.values if isinstance(template_or_values, Template) else (template_or_values or {})
    site = values.get("site") if isinstance(values, dict) else ""
    return str(site or "All Sites")


def can_manage_template(user, perm, template_or_values):
    """Templates are shared by the whole tenant; one that defaults to a site may be managed by that site's
    operators (admins for deletes), any other template only with the permission across the tenant."""
    return can_manage(user, perm, template_site(template_or_values))


def site_names(user=None):
    """Site names from core.Site, limited to what the user may see."""
    from core.access import visible_sites
    from core.models import Site
    names = list(Site.objects.filter(tenant_key=tenant()).values_list("name", flat=True))
    if user is not None:
        vis = visible_sites(user)
        if vis is not None:
            names = [n for n in names if n in vis]
    return names


# ------------------------------------------------------------------ helpers
def _excerpt(raw):
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    raw = str(raw)
    return raw if len(raw) <= EXCERPT_CHARS else raw[:EXCERPT_CHARS] + "…"


def _jsonable(payload):
    if payload is None:
        return {}
    try:
        return json.loads(json.dumps(payload, default=str))
    except (TypeError, ValueError):
        return {"value": str(payload)}


def _finish(ex, status, http_status=None, response="", error=""):
    ex.status = status
    ex.http_status = http_status
    ex.response_excerpt = _excerpt(response)
    ex.error = (error or "")[:500]
    ex.finished_at = timezone.now()
    if ex.pk:
        ex.save(update_fields=["status", "http_status", "response_excerpt", "error", "finished_at"])
    return ex


def _start(kind, trigger, payload, triggered_by="", rule=None, event=None, site=""):
    """Create the pending Execution row. On a database error return an unsaved instance (callers never break)."""
    fields = dict(tenant_key=tenant(), kind=kind, trigger=str(trigger or "")[:500], payload=_jsonable(payload),
                  status="pending", triggered_by=str(triggered_by or "")[:150], rule=rule,
                  site=(site or getattr(event, "site", "") or "")[:100],
                  event_id=getattr(event, "pk", None), fingerprint=fingerprint_for(event) if event is not None else "")
    try:
        return Execution.objects.create(**fields)
    except Exception:
        log.exception("could not record %s execution", kind)
        return Execution(**fields)


def stackstorm_configured():
    return bool(getattr(settings, "STACKSTORM_URL", ""))


def stackstorm_endpoint(trigger=""):
    base = (getattr(settings, "STACKSTORM_URL", "") or "").strip()
    if not base:
        return ""
    return base.rstrip("/") + "/" + str(trigger or "").lstrip("/") if trigger else base


def stackstorm_display_url():
    """The configured URL without credentials or query string, for display."""
    base = stackstorm_endpoint()
    if not base:
        return ""
    p = urlsplit(base)
    host = p.hostname or ""
    if p.port:
        host += f":{p.port}"
    return f"{p.scheme}://{host}{p.path}"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects from StackStorm: urllib would re-send the St2-Api-Key header to whatever host the
    Location names (and turn the POST into a GET to an arbitrary, unchecked address)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_st2_opener = urllib.request.build_opener(_NoRedirect)


def _st2_open(req, timeout=ST2_TIMEOUT):
    return _st2_opener.open(req, timeout=timeout)


def valid_trigger(trigger):
    trigger = str(trigger or "").strip()
    return bool(TRIGGER_RE.match(trigger)) and ".." not in trigger and "//" not in trigger


# ------------------------------------------------------------------ StackStorm
def trigger_stackstorm(trigger, payload, triggered_by="", rule=None, event=None, site=""):
    """POST `payload` as JSON to settings.STACKSTORM_URL + trigger with the St2-Api-Key header.

    Records and returns an Execution; never raises. When StackStorm is not configured the execution is recorded
    as failed with a 'not configured' error so the attempt is still visible.
    """
    trigger = str(trigger or "").strip()
    try:
        ex = _start("stackstorm", trigger, payload, triggered_by, rule, event, site)
    except Exception:  # pragma: no cover - _start already guards the database
        log.exception("stackstorm: could not start execution")
        return Execution(kind="stackstorm", trigger=trigger[:500], status="failed", error="internal error")
    try:
        if not stackstorm_configured():
            return _finish(ex, "failed", error="StackStorm is not configured (set LINKEDEYE_STACKSTORM_URL).")
        if not valid_trigger(trigger):
            return _finish(ex, "failed", error="Invalid trigger name: use letters, digits, '.', '_', '-' and '/'.")
        url = stackstorm_endpoint(trigger)
        body = json.dumps(ex.payload, default=str).encode()
        headers = {"Content-Type": "application/json", "Accept": "application/json", "User-Agent": "LinkedEye-Automation/1.0"}
        if getattr(settings, "STACKSTORM_API_KEY", ""):
            headers["St2-Api-Key"] = settings.STACKSTORM_API_KEY
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with _st2_open(req, timeout=ST2_TIMEOUT) as r:  # operator-configured URL; redirects are refused
                code = r.status
                raw = r.read(MAX_RESPONSE)
        except urllib.error.HTTPError as e:
            raw = b""
            try:
                raw = e.read(MAX_RESPONSE)
            except Exception:
                pass
            err = f"StackStorm returned HTTP {e.code}"
            if 300 <= e.code < 400:
                err += " (redirect not followed; set LINKEDEYE_STACKSTORM_URL to the final URL)"
            return _finish(ex, "failed", http_status=e.code, response=raw, error=err)
        except (urllib.error.URLError, TimeoutError, socket.timeout, OSError) as e:
            return _finish(ex, "failed", error=f"StackStorm unreachable: {getattr(e, 'reason', e)}")
        if 200 <= code < 300:
            return _finish(ex, "success", http_status=code, response=raw)
        return _finish(ex, "failed", http_status=code, response=raw, error=f"StackStorm returned HTTP {code}")
    except Exception as e:
        log.exception("stackstorm trigger %s failed", trigger)
        return _finish(ex, "failed", error=f"Unexpected error: {e.__class__.__name__}")


def test_stackstorm():
    """GET the configured StackStorm URL. Returns (ok, message). Never raises."""
    if not stackstorm_configured():
        return False, "StackStorm is not configured (set LINKEDEYE_STACKSTORM_URL)."
    headers = {"Accept": "application/json", "User-Agent": "LinkedEye-Automation/1.0"}
    if getattr(settings, "STACKSTORM_API_KEY", ""):
        headers["St2-Api-Key"] = settings.STACKSTORM_API_KEY
    req = urllib.request.Request(stackstorm_endpoint(), headers=headers, method="GET")
    try:
        with _st2_open(req, timeout=ST2_TIMEOUT) as r:  # operator-configured URL; redirects are refused
            return True, f"StackStorm answered HTTP {r.status}."
    except urllib.error.HTTPError as e:
        if 300 <= e.code < 400:
            return False, (f"StackStorm answered with a redirect (HTTP {e.code}); redirects are not followed. "
                           "Set LINKEDEYE_STACKSTORM_URL to the final webhook URL.")
        if e.code in (401, 403):
            return False, f"StackStorm rejected the API key (HTTP {e.code}). Check LINKEDEYE_STACKSTORM_API_KEY."
        if e.code in (404, 405):
            return True, f"StackStorm is reachable (HTTP {e.code} for a GET on the webhook URL is expected)."
        return False, f"StackStorm returned HTTP {e.code}."
    except (urllib.error.URLError, TimeoutError, socket.timeout, OSError) as e:
        return False, f"StackStorm unreachable: {getattr(e, 'reason', e)}"
    except Exception as e:
        log.exception("stackstorm connection test failed")
        return False, f"Unexpected error: {e.__class__.__name__}"


# ------------------------------------------------------------------ webhooks (SSRF-guarded)
class WebhookError(ValueError):
    pass


def check_webhook_url(url):
    """Validate scheme and resolve the host through the probes SSRF policy. Returns (parts, port, ip).
    Raises WebhookError with a user-safe message."""
    from probes import checks
    url = str(url or "").strip()
    p = urlsplit(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise WebhookError("Webhook URL must start with http:// or https:// and name a host.")
    if p.username or p.password:
        raise WebhookError("Webhook URL must not contain credentials.")
    try:
        port = p.port or (443 if p.scheme == "https" else 80)
    except ValueError:
        raise WebhookError("Webhook URL has an invalid port.") from None
    try:
        ip = checks.resolve_allowed(p.hostname, port)
    except checks.ProbeBlocked as e:
        raise WebhookError(f"Webhook target refused by the probe policy: {e}") from None
    except (socket.gaierror, UnicodeError, OSError) as e:
        raise WebhookError(f"Webhook host {p.hostname} did not resolve ({e.__class__.__name__}).") from None
    return p, port, ip


def validate_webhook_url(url):
    """Form validator wrapper."""
    try:
        check_webhook_url(url)
    except WebhookError as e:
        raise ValidationError(str(e)) from None


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, ip, port, timeout):
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, ip, port, timeout, context):
        super().__init__(host, port, timeout=timeout, context=context)
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _post_pinned(parts, port, ip, body, timeout):
    if parts.scheme == "https":
        conn = _PinnedHTTPS(parts.hostname, ip, port, timeout, ssl.create_default_context())
    else:
        conn = _PinnedHTTP(parts.hostname, ip, port, timeout)
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    try:
        conn.request("POST", path, body=body, headers={"Content-Type": "application/json", "Accept": "application/json",
                                                        "User-Agent": "LinkedEye-Automation/1.0"})
        resp = conn.getresponse()
        return resp.status, resp.read(MAX_RESPONSE)
    finally:
        conn.close()


def post_webhook(url, payload, triggered_by="", rule=None, event=None, site=""):
    """POST JSON to a webhook after the SSRF check (connects to the validated address; no redirects).
    Records and returns an Execution; never raises."""
    ex = _start("webhook", url, payload, triggered_by, rule, event, site)
    try:
        try:
            parts, port, ip = check_webhook_url(url)
        except WebhookError as e:
            return _finish(ex, "failed", error=str(e))
        body = json.dumps(ex.payload, default=str).encode()
        try:
            code, raw = _post_pinned(parts, port, ip, body, WEBHOOK_TIMEOUT)
        except (OSError, http.client.HTTPException, ssl.SSLError) as e:
            return _finish(ex, "failed", error=f"Webhook unreachable: {e.__class__.__name__}: {e}"[:500])
        if 200 <= code < 300:
            return _finish(ex, "success", http_status=code, response=raw)
        return _finish(ex, "failed", http_status=code, response=raw, error=f"Webhook returned HTTP {code}")
    except Exception as e:
        log.exception("webhook %s failed", str(url).split("?")[0])
        return _finish(ex, "failed", error=f"Unexpected error: {e.__class__.__name__}")


# ------------------------------------------------------------------ rules
def fingerprint_for(event):
    if event is None:
        return ""
    fp = getattr(event, "fingerprint", "") or f"evt:{getattr(event, 'source', '')}:{getattr(event, 'title', '')}"
    return fp[:200]


def event_payload(event, rule=None, extra=None):
    """JSON body sent to StackStorm / webhooks for a rule firing."""
    occurred = getattr(event, "occurred_at", None)
    data = getattr(event, "data", None)
    body = {
        "event": {
            "id": getattr(event, "pk", None), "source": getattr(event, "source", ""), "severity": getattr(event, "severity", ""),
            "kind": getattr(event, "kind", ""), "title": getattr(event, "title", ""), "message": getattr(event, "message", ""),
            "site": getattr(event, "site", ""), "fingerprint": getattr(event, "fingerprint", ""),
            "object_type": getattr(event, "object_type", ""), "object_id": getattr(event, "object_id", ""),
            "occurred_at": occurred.isoformat() if occurred else None, "data": data if isinstance(data, dict) else {},
        },
        "tenant": tenant(),
    }
    if rule is not None:
        body["rule"] = {"id": rule.pk, "name": rule.name}
    if isinstance(extra, dict):
        body.update(extra)
    return body


def in_cooldown(rule, event, now=None):
    if not rule.cooldown_minutes or rule.pk is None:
        return False
    now = now or timezone.now()
    return Execution.objects.filter(rule=rule, fingerprint=fingerprint_for(event),
                                    started_at__gte=now - timedelta(minutes=rule.cooldown_minutes)).exists()


def _open_incident(rule, event, triggered_by):
    p = rule.params
    data = event.data if isinstance(getattr(event, "data", None), dict) else {}
    payload = {"title": p.get("title") or event.title, "priority": p.get("priority") or "P3", "site": event.site,
               "fingerprint": fingerprint_for(event)}
    ex = _start("rule", "open_incident", payload, triggered_by, rule, event)
    try:
        from django.apps import apps
        if not apps.is_installed("servicedesk"):
            return _finish(ex, "failed", error="The Service Desk module is not installed.")
        try:
            from servicedesk import services as sd
        except ImportError:
            return _finish(ex, "failed", error="The Service Desk module is not available.")
        desc = event.message or ""
        desc += ("\n\n" if desc else "") + (f"Opened by automation rule “{rule.name}” from a {event.severity} "
                                            f"{event.source} event.")
        if rule.runbook_id:
            desc += f"\nRunbook: {rule.runbook.title}"
        ticket = sd.open_incident(title=payload["title"][:200], description=desc, priority=payload["priority"],
                                  site=event.site or "", source="automation", fingerprint=payload["fingerprint"],
                                  ci_name=str(p.get("ci_name") or data.get("ci") or data.get("ci_name") or data.get("host") or "")[:200])
        ex.result_label = str(getattr(ticket, "number", "") or ticket)[:120]
        try:
            ex.result_url = ticket.get_absolute_url()[:300]
        except Exception:
            ex.result_url = ""
        if ex.pk:
            ex.save(update_fields=["result_label", "result_url"])
        return _finish(ex, "success", response=f"Incident {ex.result_label}")
    except Exception as e:
        log.exception("rule %s: open_incident failed", rule.pk)
        return _finish(ex, "failed", error=f"Could not open the incident: {e.__class__.__name__}: {e}"[:500])


def _link_runbook(rule, event, triggered_by):
    rb = rule.runbook
    ex = _start("rule", "link_runbook", {"runbook_id": rule.runbook_id, "runbook": rb.title if rb else ""},
                triggered_by, rule, event)
    if rb is None:
        return _finish(ex, "failed", error="The rule's runbook no longer exists.")
    ex.result_label = rb.title[:120]
    ex.result_url = rb.get_absolute_url()[:300]
    if ex.pk:
        ex.save(update_fields=["result_label", "result_url"])
    return _finish(ex, "success", response=f"Runbook “{rb.title}” linked to {event.title}")


def run_action(rule, event, triggered_by="rule"):
    """Run the rule's action for an event. Returns the Executions recorded. Never raises."""
    p = rule.params
    extra = p.get("payload") if isinstance(p.get("payload"), dict) else None
    try:
        if rule.action == "open_incident":
            return [_open_incident(rule, event, triggered_by)]
        if rule.action == "stackstorm":
            return [trigger_stackstorm(p.get("trigger", ""), event_payload(event, rule, extra), triggered_by, rule, event)]
        if rule.action == "webhook":
            return [post_webhook(p.get("url", ""), event_payload(event, rule, extra), triggered_by, rule, event)]
        if rule.action == "link_runbook":
            return [_link_runbook(rule, event, triggered_by)]
        ex = _start("rule", rule.action, {}, triggered_by, rule, event)
        return [_finish(ex, "failed", error=f"Unknown action “{rule.action}”.")]
    except Exception as e:
        log.exception("rule %s action failed", rule.pk)
        ex = _start("rule", rule.action, {}, triggered_by, rule, event)
        return [_finish(ex, "failed", error=f"Unexpected error: {e.__class__.__name__}")]


def fire(rule, event, triggered_by=""):
    """Run a rule's action for an event, update the rule and emit an info event. Returns the Executions."""
    triggered_by = triggered_by or "automation"
    prev = getattr(_state, "busy", False)
    _state.busy = True   # events emitted by the action itself (e.g. the new incident) must not re-enter the rules
    try:
        executions = run_action(rule, event, triggered_by)
        now = timezone.now()
        Rule.objects.filter(pk=rule.pk).update(last_fired_at=now, fire_count=F("fire_count") + 1)
        rule.last_fired_at = now
        failed = [e for e in executions if e.status == "failed"]
        try:
            from core.events import emit
            outcome = "failed" if failed else "succeeded"
            emit(source="automation", title=f"Rule “{rule.name}” fired: {rule.action_summary()} {outcome}"[:200],
                 severity="info", kind="automation",
                 message=(f"Matched {event.severity} {event.source} event “{event.title}”."
                          + (f" Error: {failed[0].error}" if failed else "")),
                 site=getattr(event, "site", "") or "", obj=rule, fingerprint=f"automation:rule:{rule.pk}",
                 rule=rule.name, action=rule.action, event_id=getattr(event, "pk", None), status=outcome,
                 executions=[e.pk for e in executions if e.pk], result=", ".join(e.result_label for e in executions if e.result_label))
        except Exception:
            log.exception("could not emit automation event for rule %s", rule.pk)
        return executions
    finally:
        _state.busy = prev


def evaluate_event(event):
    """Run every enabled rule that matches the event (outside its cooldown). Returns the Executions recorded."""
    if getattr(_state, "busy", False):
        return []
    if str(getattr(event, "source", "")).lower() == "automation":
        return []
    tk = getattr(event, "tenant_key", "") or tenant()
    out = []
    # When the emitter is inside a transaction, isolate each rule in a savepoint so a database error here can never
    # break the caller's transaction. Outside a transaction no wrapping is needed (and none is wanted around
    # network calls).
    nested = transaction.get_connection().in_atomic_block
    for rule in Rule.objects.filter(tenant_key=tk, enabled=True).select_related("runbook"):
        try:
            if not rule.matches(event) or in_cooldown(rule, event):
                continue
            if nested:
                with transaction.atomic():
                    out.extend(fire(rule, event))
            else:
                out.extend(fire(rule, event))
        except Exception:
            log.exception("rule %s failed for event %s", rule.pk, getattr(event, "pk", None))
    return out


# ------------------------------------------------------------------ jobs
def housekeeping(now=None):
    """Fail executions stuck in 'pending' (process died mid-call) and prune old executions. Never raises."""
    now = now or timezone.now()
    try:
        stale = Execution.objects.filter(status="pending", started_at__lt=now - timedelta(minutes=STALE_PENDING_MINUTES))
        n_stale = stale.update(status="failed", finished_at=now, error="Interrupted: no result was recorded.")
        days = int(getattr(settings, "AUTOMATION_RETENTION_DAYS", RETENTION_DAYS_DEFAULT) or RETENTION_DAYS_DEFAULT)
        n_old, _ = Execution.objects.filter(started_at__lt=now - timedelta(days=days)).delete()
        return f"{n_stale} stale, {n_old} pruned"
    except Exception:
        log.exception("automation housekeeping failed")
        return "error"


# ------------------------------------------------------------------ templates
class ApplyError(Exception):
    """Applying a template failed. `errors` maps form field names to messages (or "__all__")."""

    def __init__(self, errors):
        super().__init__("; ".join(f"{k}: {v}" for k, v in errors.items()))
        self.errors = errors


def _get_model(label):
    from django.apps import apps
    try:
        return apps.get_model(label)
    except (LookupError, ValueError):
        raise ApplyError({"__all__": f"The module that provides {label} is not installed."}) from None


def _create_checked(model, values):
    obj = model(tenant_key=tenant(), **values)
    try:
        obj.full_clean()
    except ValidationError as e:
        errs = {}
        for k, msgs in e.message_dict.items():
            text = " ".join(msgs)
            if k not in values and "name" in values and "already exists" in text and "name" in text.lower():
                # (tenant_key, name) uniqueness is reported as a non-field error naming the internal tenant key
                k, text = "name", f"A {model._meta.verbose_name} named “{values['name']}” already exists."
            key = k if k in values else "__all__"
            errs[key] = f"{errs[key]} {text}" if key in errs else text
        raise ApplyError(errs) from None
    with transaction.atomic():
        obj.save()
    return obj


def apply_template(template, values, user=None):
    """Create the record a template describes from the confirmed `values`.
    Returns (obj, url, label). Raises ApplyError."""
    from django.urls import NoReverseMatch, reverse
    kind = template.kind
    if kind == "url_check":
        obj = _create_checked(_get_model("urlchecker.UrlCheck"), values)
        try:
            url = reverse("urlchecker:detail", args=[obj.pk])
        except NoReverseMatch:
            url = ""
        return obj, url, f"URL check “{obj.name}”"
    if kind == "tcp_check":
        obj = _create_checked(_get_model("tcpcheck.TcpCheck"), values)
        try:
            url = obj.get_absolute_url()
        except Exception:
            url = ""
        return obj, url, f"TCP check “{obj.name}”"
    if kind == "incident":
        from django.apps import apps
        if not apps.is_installed("servicedesk"):
            raise ApplyError({"__all__": "The Service Desk module is not installed."})
        try:
            from servicedesk import services as sd
        except ImportError:
            raise ApplyError({"__all__": "The Service Desk module is not available."}) from None
        desc = values.get("description", "")
        desc += ("\n\n" if desc else "") + f"Created from template “{template.name}” by {_name(user) or 'automation'}."
        ticket = sd.open_incident(title=values["title"], description=desc, priority=values.get("priority") or "P3",
                                  site=values.get("site", ""), source="automation", fingerprint="",
                                  ci_name=values.get("ci_name", ""))
        try:
            url = ticket.get_absolute_url()
        except Exception:
            url = ""
        return ticket, url, f"Incident {getattr(ticket, 'number', '') or ticket}"
    if kind == "notification":
        from core.events import emit
        ev = emit(source="automation", title=values["title"], severity=values.get("severity") or "warning",
                  message=values.get("message", ""), kind="notification", site=values.get("site", ""),
                  obj=template, fingerprint=f"automation:template:{template.pk}", template=template.name,
                  sent_by=_name(user))
        return ev, "", f"{ev.get_severity_display()} notification event #{ev.pk}"
    raise ApplyError({"__all__": f"Unknown template kind “{kind}”."})
