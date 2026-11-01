"""Service desk operations. Views, the event listener and other modules all go through these functions so
every change writes a timeline entry and emits an event the same way.

Cross-module interface (docs/MODULES.md):
    open_incident(title, description="", priority="P3", site="", source="", fingerprint="", ci_name="") -> Ticket
    resolve_by_fingerprint(fingerprint, note="")
"""
import logging

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from . import sla
from . import workflow as wf

log = logging.getLogger("linkedeye.servicedesk")


class WorkflowError(ValueError):
    """A transition or change that is not allowed in the ticket's current state."""


def _name(user):
    if user is None or not getattr(user, "is_authenticated", False):
        return ""
    return user.get_full_name() or user.get_username()


def _note(ticket, kind, body, user=None, author_name="", old="", new=""):
    from .models import TimelineEntry
    return TimelineEntry.objects.create(ticket=ticket, kind=kind, body=body, old_value=str(old)[:100], new_value=str(new)[:100],
                                        author=user if user is not None and getattr(user, "is_authenticated", False) else None,
                                        author_name=_name(user) or author_name or "system")


def _emit(ticket, title, severity="info", message="", kind="state_change", **data):
    try:
        from core.events import emit
        emit(source="servicedesk", title=f"{ticket.number} {title}"[:200], severity=severity, message=message or ticket.title,
             kind=kind, site=ticket.site, obj=ticket, fingerprint=f"servicedesk:{ticket.pk}",
             number=ticket.number, ticket_kind=ticket.kind, status=ticket.status, priority=ticket.priority, **data)
    except Exception:  # an event failure must never undo the ticket change
        log.exception("could not emit event for %s", ticket.number)


def _created_severity(ticket):
    if ticket.kind == "incident":
        return {"P1": "critical", "P2": "warning"}.get(ticket.priority, "info")
    return "info"


def _normalise_source(source):
    """Map a free-text source (e.g. a module name) to (source, origin)."""
    keys = {k for k, _ in wf.SOURCES}
    source = (source or "").strip()
    if not source:
        return "manual", ""
    if source in keys:
        return source, ""
    return "alert", source[:40]


# ---------------------------------------------------------------- creation
def create_ticket(user=None, **fields):
    """Create a ticket (any kind), its 'opened' timeline entry and an event."""
    from .models import Ticket
    kind = fields.get("kind") or "incident"
    fields.setdefault("status", wf.INITIAL[kind])
    fields.setdefault("tenant_key", settings.LINKEDEYE_TENANT)
    if user is not None and getattr(user, "is_authenticated", False):
        fields.setdefault("reporter", user)
        fields.setdefault("reporter_name", _name(user))
    with transaction.atomic():
        t = Ticket(**fields)
        t.save()
        via = {"alert": " from an alert", "automation": " by automation", "catalog": " from the service catalog"}.get(t.source, "")
        _note(t, "system", f"{t.get_kind_display()} opened{via}.", user, author_name=t.reporter_name or t.origin,
              new=t.status)
        if t.assignee_id:
            _note(t, "assignment", f"Assigned to {_name(t.assignee)}.", user, author_name=t.reporter_name, new=t.assignee.get_username())
    _emit(t, f"opened: {t.title}", severity=_created_severity(t), message=t.description or t.title, kind="ticket_opened")
    return t


def open_incident(title, description="", priority="P3", site="", source="", fingerprint="", ci_name="", **extra):
    """Open an incident, or — when an open incident already has this fingerprint — add a timeline note to it
    instead of creating a duplicate. Returns the (new or existing) Ticket."""
    from .models import Ticket
    priority = priority if priority in wf.PRIORITY_LABELS else "P3"
    src, origin = _normalise_source(source)
    fingerprint = (fingerprint or "")[:200]
    if fingerprint:
        existing = (Ticket.objects.for_tenant().open().filter(kind="incident", fingerprint=fingerprint).order_by("-opened_at").first())
        if existing:
            _note(existing, "system", f"Duplicate alert received{' from ' + (origin or src) if (origin or src) else ''}: {title}"
                  + (f"\n{description}" if description else ""), author_name=origin or "alert")
            changed = []
            if priority < existing.priority:   # "P1" < "P2": escalate, never downgrade
                old = existing.priority
                existing.priority = priority
                sla.apply_due_dates(existing)
                existing.save(update_fields=["priority", "response_due", "resolution_due", "updated_at"])
                _note(existing, "priority", f"Priority raised from {old} to {priority} by a new alert.", author_name=origin or "alert",
                      old=old, new=priority)
                changed.append("priority")
            if existing.status == "mitigated":   # the problem came back
                existing.status = "investigating"
                existing.save(update_fields=["status", "updated_at"])
                _note(existing, "status", "Alert fired again: back to Investigating.", author_name=origin or "alert",
                      old="mitigated", new="investigating")
                changed.append("status")
            if changed:
                _emit(existing, f"re-alerted: {existing.title}", severity="warning", kind="ticket_updated")
            return existing
    return create_ticket(kind="incident", title=(title or "Untitled incident")[:200], description=description or "",
                         priority=priority, site=site or "", source=src, origin=origin, fingerprint=fingerprint,
                         ci_name=(ci_name or "")[:200], reporter_name=extra.pop("reporter_name", "") or origin or src,
                         **{k: v for k, v in extra.items() if k in ("category", "client")})


def resolve_by_fingerprint(fingerprint, note=""):
    """Resolve every open incident carrying this fingerprint. Returns how many were resolved."""
    from .models import Ticket
    if not fingerprint:
        return 0
    n = 0
    for t in Ticket.objects.for_tenant().open().filter(kind="incident", fingerprint=fingerprint):
        transition(t, "resolved", user=None, note=note or "Resolved automatically: the alert cleared.", actor_name="automation",
                   force=True)
        n += 1
    return n


def request_from_catalog(item, user, details="", site="", client=""):
    return create_ticket(user=user, kind="request", title=f"Request: {item.name}"[:200], description=details or item.description,
                         priority=item.default_priority, category=item.category, catalog_item=item, source="catalog",
                         site=site, client=client)


# ---------------------------------------------------------------- changes
def transition(ticket, target, user=None, note="", actor_name="", force=False):
    """Move a ticket to `target` if the workflow allows it from its current status.

    force=True lets automation move an incident to resolved from any open state (resolve_by_fingerprint)."""
    old = ticket.status
    if target == old:
        raise WorkflowError(f"{ticket.number} is already {wf.STATUS_LABELS.get(old, old)}.")
    if not (wf.allowed(ticket.kind, old, target) or (force and target == "resolved" and ticket.is_open and ticket.kind == "incident")):
        raise WorkflowError(f"{ticket.get_kind_display()} {ticket.number} cannot move from "
                            f"{wf.STATUS_LABELS.get(old, old)} to {wf.STATUS_LABELS.get(target, target)}.")
    if ticket.kind == "change" and target == "approved" and old == "submitted" and user is not None:
        from core.access import can
        if ticket.reporter_id == user.pk and not can(user, "admin"):
            raise WorkflowError("A change must be approved by someone other than its requester (or an admin).")
    if ticket.kind == "change" and target == "scheduled" and not (ticket.planned_start and ticket.planned_end):
        raise WorkflowError("Set the planned start and end of the change window before scheduling it.")
    if ticket.kind == "change" and target == "scheduled" and ticket.planned_end <= ticket.planned_start:
        raise WorkflowError("The planned end must be after the planned start.")

    now = timezone.now()
    reopen = wf.is_reopen(old, target)
    if old == wf.INITIAL[ticket.kind] and ticket.acknowledged_at is None and target not in ("draft",):
        ticket.acknowledged_at = now
    if target in wf.RESOLVING and ticket.resolved_at is None:
        ticket.resolved_at = now
    if target in wf.FINAL:
        ticket.closed_at = now
        if target == "closed" and ticket.resolved_at is None:
            ticket.resolved_at = now
    if reopen:
        ticket.resolved_at = None
        ticket.closed_at = None
    if ticket.kind == "change":
        if target == "approved" and old == "submitted":
            ticket.approved_by = user if user is not None and getattr(user, "is_authenticated", False) else None
            ticket.approved_at = now
        if target in ("draft", "rejected"):
            ticket.approved_by, ticket.approved_at = None, None
    if note and target in wf.RESOLVING:
        ticket.resolution = note
    ticket.status = target
    with transaction.atomic():
        ticket.save()
        label = "Reopened" if reopen else f"Status changed to {wf.STATUS_LABELS[target]}"
        _note(ticket, "status", label + (f": {note}" if note else "."), user, author_name=actor_name, old=old, new=target)
        sla.check(ticket, now)
    sev = "ok" if target in wf.RESOLVING else "info"
    if reopen and ticket.kind == "incident":
        sev = _created_severity(ticket)
    _emit(ticket, f"{'reopened' if reopen else wf.STATUS_LABELS[target].lower()}: {ticket.title}", severity=sev,
          message=note or ticket.title, kind="ticket_status", previous=old)
    return ticket


def assign(ticket, assignee, user=None):
    old = ticket.assignee
    if (old.pk if old else None) == (assignee.pk if assignee else None):
        return ticket
    ticket.assignee = assignee
    ticket.save(update_fields=["assignee", "updated_at"])
    text = f"Assigned to {_name(assignee)}." if assignee else "Unassigned."
    if old and assignee:
        text = f"Reassigned from {_name(old)} to {_name(assignee)}."
    _note(ticket, "assignment", text, user, old=old.get_username() if old else "", new=assignee.get_username() if assignee else "")
    _emit(ticket, f"assigned to {_name(assignee)}" if assignee else "unassigned", kind="ticket_assigned",
          assignee=assignee.get_username() if assignee else "")
    return ticket


def set_priority(ticket, priority, user=None):
    if priority not in wf.PRIORITY_LABELS:
        raise WorkflowError("Unknown priority.")
    old = ticket.priority
    if old == priority:
        return ticket
    ticket.priority = priority
    if ticket.kind in wf.SLA_KINDS:
        sla.apply_due_dates(ticket)
    ticket.save(update_fields=["priority", "response_due", "resolution_due", "updated_at"])
    _note(ticket, "priority", f"Priority changed from {old} ({wf.PRIORITY_LABELS[old]}) to {priority} ({wf.PRIORITY_LABELS[priority]}).",
          user, old=old, new=priority)
    sla.check(ticket)
    sev = "warning" if ticket.kind == "incident" and priority == "P1" and ticket.is_open else "info"
    _emit(ticket, f"priority {old} → {priority}", severity=sev, kind="ticket_priority", previous=old)
    return ticket


def comment(ticket, body, user=None, author_name=""):
    body = (body or "").strip()
    if not body:
        raise WorkflowError("A comment cannot be empty.")
    return _note(ticket, "comment", body[:10000], user, author_name=author_name)


def link_problem(incident, problem, user=None):
    if incident.kind != "incident" or (problem is not None and problem.kind != "problem"):
        raise WorkflowError("Only incidents can be linked to problems.")
    old = incident.problem
    if (old.pk if old else None) == (problem.pk if problem else None):
        return incident
    incident.problem = problem
    incident.save(update_fields=["problem", "updated_at"])
    if problem:
        _note(incident, "link", f"Linked to problem {problem.number}.", user, new=problem.number)
        _note(problem, "link", f"Incident {incident.number} linked.", user, new=incident.number)
    else:
        _note(incident, "link", f"Unlinked from problem {old.number}.", user, old=old.number)
        _note(old, "link", f"Incident {incident.number} unlinked.", user, old=incident.number)
    return incident


def add_ci(ticket, ci_name, user=None, note=""):
    from .models import TicketCI
    ci_name = (ci_name or "").strip()[:200]
    if not ci_name:
        raise WorkflowError("Enter a configuration item name.")
    link, created = TicketCI.objects.get_or_create(ticket=ticket, ci_name=ci_name, defaults={"note": note[:200]})
    if created:
        _note(ticket, "link", f"Configuration item {ci_name} added.", user, new=ci_name)
    return link


def remove_ci(link, user=None):
    ticket, name = link.ticket, link.ci_name
    link.delete()
    _note(ticket, "link", f"Configuration item {name} removed.", user, old=name)


def record_edit(ticket, changed, user=None):
    """Timeline entry + event after the edit form saved `changed` (list of field labels)."""
    if not changed:
        return
    _note(ticket, "edit", "Updated " + ", ".join(changed) + ".", user)
    _emit(ticket, "updated", kind="ticket_updated", fields=changed)


def find_ci(name):
    """Look a CI up in the CMDB module when it is installed (None otherwise)."""
    if not name:
        return None
    try:
        from django.apps import apps
        if not apps.is_installed("cmdb"):
            return None
        from cmdb.services import find_ci as cmdb_find  # noqa: WPS433 (optional dependency)
        return cmdb_find(name)
    except Exception:
        return None
