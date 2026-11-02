"""SLA due dates, live clock state and breach flagging.

* Response is met when the ticket leaves its initial state (acknowledged_at).
* Resolution is met when the ticket is resolved/fulfilled (resolved_at).
* Only incidents and service requests carry SLAs. A request raised from the catalog uses the catalog
  item's fulfilment hours as its resolution target.
* A breach is flagged exactly once (flag + timeline entry + one warning event) by `check()`, which the
  `servicedesk.sla` job runs every 60 s and which transitions call immediately.
"""
import logging
from datetime import timedelta

from django.db.models import Q
from django.utils import timezone

from . import workflow as wf

log = logging.getLogger("linkedeye.servicedesk")

AT_RISK_FRACTION = 0.25      # open tickets with less than 25 % of the resolution window left are "at risk"
JOB_BATCH = 500

DEFAULT_POLICIES = [
    # priority, name, response minutes, resolution minutes
    ("P1", "Critical", 15, 4 * 60),
    ("P2", "High", 30, 8 * 60),
    ("P3", "Medium", 4 * 60, 24 * 60),
    ("P4", "Low", 8 * 60, 72 * 60),
]


def policy_for(ticket):
    from .models import SlaPolicy
    return SlaPolicy.objects.filter(tenant_key=ticket.tenant_key, priority=ticket.priority, active=True).first()


def apply_due_dates(ticket):
    """Set response_due / resolution_due from the policy for the ticket's priority (counted from opened_at)."""
    if ticket.kind not in wf.SLA_KINDS:
        ticket.response_due = ticket.resolution_due = None
        return ticket
    policy = policy_for(ticket)
    opened = ticket.opened_at or timezone.now()
    ticket.response_due = _after(opened, minutes=policy.response_minutes) if policy else None
    ticket.resolution_due = _after(opened, minutes=policy.resolution_minutes) if policy else None
    item = ticket.catalog_item if ticket.catalog_item_id else None
    if ticket.kind == "request" and item and item.fulfilment_hours:
        ticket.resolution_due = _after(opened, hours=item.fulfilment_hours)
    return ticket


def _after(start, **delta):
    """start + delta, or None when the target is beyond the calendar (a bad policy must never block ticket creation)."""
    try:
        return start + timedelta(**delta)
    except OverflowError:
        log.warning("SLA target %s from %s is out of range; no due date set", delta, start)
        return None


def _late(due, done_at, status, now):
    return bool(due) and ((done_at is not None and done_at > due) or (done_at is None and status not in wf.DONE and now > due))


def clear_stale_breaches(ticket, now=None):
    """After the due dates were recomputed (priority change): drop breach flags that no longer hold under the new
    targets. Sets the attributes only (the caller saves); returns the clocks cleared."""
    now = now or timezone.now()
    cleared = []
    if ticket.response_breached and not _late(ticket.response_due, ticket.acknowledged_at, ticket.status, now):
        ticket.response_breached = False
        cleared.append("response")
    if ticket.resolution_breached and not _late(ticket.resolution_due, ticket.resolved_at, ticket.status, now):
        ticket.resolution_breached = False
        cleared.append("resolution")
    return cleared


def fmt_minutes(minutes):
    minutes = int(abs(minutes))
    if minutes < 60:
        return f"{minutes}m"
    if minutes < 24 * 60:
        h, m = divmod(minutes, 60)
        return f"{h}h {m}m" if m and h < 10 else f"{h}h"
    d, rem = divmod(minutes, 24 * 60)
    return f"{d}d {rem // 60}h" if rem // 60 else f"{d}d"


def clock(due, done_at, start, breached, now=None):
    """State of one SLA clock: none | met | breached | at_risk | on_track, with remaining/overdue text."""
    now = now or timezone.now()
    if due is None:
        return {"state": "none", "label": "No SLA", "tone": "mute", "text": "–", "due": None, "pct": None}
    if done_at is not None:
        late = done_at > due or breached
        return {"state": "breached" if late else "met", "label": "Breached" if late else "Met", "tone": "crit" if late else "ok",
                "text": ("late by " + fmt_minutes((done_at - due).total_seconds() / 60)) if done_at > due else "met",
                "due": due, "pct": 100}
    left = (due - now).total_seconds() / 60
    window = max(1.0, (due - start).total_seconds() / 60) if start else 1.0
    used = min(100, max(0, round(100 * (1 - left / window))))
    if left < 0 or breached:
        return {"state": "breached", "label": "Breached", "tone": "crit", "text": "-" + fmt_minutes(left) if left < 0 else "breached",
                "due": due, "pct": 100}
    risky = left < window * AT_RISK_FRACTION
    return {"state": "at_risk" if risky else "on_track", "label": "At Risk" if risky else "On Track",
            "tone": "warn" if risky else "ok", "text": fmt_minutes(left), "due": due, "pct": used}


def response_clock(t, now=None):
    return clock(t.response_due, t.acknowledged_at, t.opened_at, t.response_breached, now)


def resolution_clock(t, now=None):
    return clock(t.resolution_due, t.resolved_at, t.opened_at, t.resolution_breached, now)


def overall(t, now=None):
    """Single SLA state for a ticket: breached > at_risk > on_track > met > none."""
    if t.response_due is None and t.resolution_due is None:
        return "none"
    if t.response_breached or t.resolution_breached:
        return "breached"
    res, resp = resolution_clock(t, now), response_clock(t, now)
    states = {res["state"], resp["state"]}
    for s in ("breached", "at_risk", "on_track"):
        if s in states:
            return s
    return "met"


def check(ticket, now=None, emit_events=True):
    """Flag new breaches on one ticket. Returns the list of clocks newly breached ("response"/"resolution")."""
    now = now or timezone.now()
    new = []
    if ticket.response_due and not ticket.response_breached:
        if (ticket.acknowledged_at and ticket.acknowledged_at > ticket.response_due) or \
                (not ticket.acknowledged_at and ticket.status not in wf.DONE and now > ticket.response_due):
            new.append("response")
    if ticket.resolution_due and not ticket.resolution_breached:
        if (ticket.resolved_at and ticket.resolved_at > ticket.resolution_due) or \
                (not ticket.resolved_at and ticket.status not in wf.DONE and now > ticket.resolution_due):
            new.append("resolution")
    if not new:
        return new
    from .models import Ticket, TimelineEntry
    fields = {f"{w}_breached": True for w in new}
    # conditional update so concurrent checkers cannot flag (and announce) the same breach twice
    cond = Q()
    for w in new:
        cond &= Q(**{f"{w}_breached": False})
    if not Ticket.objects.filter(pk=ticket.pk).filter(cond).update(**fields):
        return []
    for k, v in fields.items():
        setattr(ticket, k, v)
    for w in new:
        due = ticket.response_due if w == "response" else ticket.resolution_due
        TimelineEntry.objects.create(ticket=ticket, kind="sla", author_name="SLA monitor", new_value=f"{w}_breached",
                                     body=f"{w.title()} SLA breached (was due {timezone.localtime(due):%d %b %H:%M}).")
        if emit_events:
            try:
                from core.events import emit
                emit(source="servicedesk", title=f"SLA breach: {ticket.number} {ticket.title}"[:200], severity="warning",
                     message=f"{w.title()} target for {ticket.number} ({ticket.priority} {ticket.get_kind_display()}) "
                             f"was due {timezone.localtime(due):%d %b %Y %H:%M}.",
                     kind="sla_breach", site=ticket.site, obj=ticket, fingerprint=f"servicedesk:sla:{ticket.pk}:{w}",
                     number=ticket.number, clock=w, priority=ticket.priority)
            except Exception:  # never let event delivery break the job
                log.exception("could not emit SLA breach event for %s", ticket.number)
    return new


def flag_breaches(now=None):
    """Periodic job: flag every open ticket whose response or resolution target has passed."""
    from .models import Ticket
    now = now or timezone.now()
    due = (Ticket.objects.for_tenant().exclude(status__in=wf.DONE)
           .filter(Q(response_due__lt=now, response_breached=False, acknowledged_at__isnull=True)
                   | Q(resolution_due__lt=now, resolution_breached=False, resolved_at__isnull=True))
           .order_by("resolution_due")[:JOB_BATCH])
    flagged = 0
    for t in due:
        try:
            flagged += len(check(t, now))
        except Exception:
            log.exception("SLA check failed for ticket %s", t.pk)
    return f"{flagged} SLA breach(es) flagged" if flagged else "no new SLA breaches"
