"""Ticket kinds, per-kind status workflows and the transitions allowed from each state.

Every status key is unique across kinds so one CharField can hold them all.
"""

KINDS = [("incident", "Incident"), ("problem", "Problem"), ("change", "Change"), ("request", "Service Request")]
KIND_LABELS = dict(KINDS)
PREFIX = {"incident": "INC", "problem": "PRB", "change": "CHG", "request": "REQ"}
KIND_BY_PREFIX = {v: k for k, v in PREFIX.items()}
# URL section of each kind's list and detail pages
SECTION = {"incident": "incidents", "problem": "problems", "change": "changes", "request": "tickets"}

PRIORITIES = [("P1", "Critical"), ("P2", "High"), ("P3", "Medium"), ("P4", "Low")]
PRIORITY_LABELS = dict(PRIORITIES)

SOURCES = [("manual", "Manual"), ("alert", "Alert"), ("automation", "Automation"), ("catalog", "Service Catalog")]

RISKS = [("low", "Low"), ("medium", "Medium"), ("high", "High")]

STATUSES = [
    ("new", "New"),
    ("acknowledged", "Acknowledged"),
    ("investigating", "Investigating"),
    ("mitigated", "Mitigated"),
    ("known_error", "Known Error"),
    ("resolved", "Resolved"),
    ("draft", "Draft"),
    ("submitted", "Submitted"),
    ("approved", "Approved"),
    ("scheduled", "Scheduled"),
    ("implemented", "Implemented"),
    ("rejected", "Rejected"),
    ("in_progress", "In Progress"),
    ("fulfilled", "Fulfilled"),
    ("closed", "Closed"),
]
STATUS_LABELS = dict(STATUSES)

# The happy path of each kind, in order (used for progress steppers and status filters).
FLOW = {
    "incident": ["new", "acknowledged", "investigating", "mitigated", "resolved", "closed"],
    "problem": ["new", "investigating", "known_error", "resolved", "closed"],
    "change": ["draft", "submitted", "approved", "scheduled", "implemented", "closed", "rejected"],
    "request": ["new", "in_progress", "fulfilled", "closed"],
}
INITIAL = {"incident": "new", "problem": "new", "change": "draft", "request": "new"}

# status -> [(target, button label, style)]; style is "primary", "ok", "danger" or "" (plain)
TRANSITIONS = {
    "incident": {
        "new": [("acknowledged", "Acknowledge", "primary"), ("investigating", "Start Investigation", ""), ("resolved", "Resolve", "ok")],
        "acknowledged": [("investigating", "Start Investigation", "primary"), ("mitigated", "Mark Mitigated", ""), ("resolved", "Resolve", "ok")],
        "investigating": [("mitigated", "Mark Mitigated", "primary"), ("resolved", "Resolve", "ok")],
        "mitigated": [("resolved", "Resolve", "ok"), ("investigating", "Back to Investigating", "")],
        "resolved": [("closed", "Close", "primary"), ("investigating", "Reopen", "danger")],
        "closed": [("investigating", "Reopen", "danger")],
    },
    "problem": {
        "new": [("investigating", "Start Investigation", "primary")],
        "investigating": [("known_error", "Mark Known Error", "primary"), ("resolved", "Resolve", "ok")],
        "known_error": [("resolved", "Resolve", "ok"), ("investigating", "Back to Investigating", "")],
        "resolved": [("closed", "Close", "primary"), ("investigating", "Reopen", "danger")],
        "closed": [],
    },
    "change": {
        "draft": [("submitted", "Submit for Approval", "primary")],
        "submitted": [("approved", "Approve", "ok"), ("rejected", "Reject", "danger"), ("draft", "Withdraw to Draft", "")],
        "approved": [("scheduled", "Schedule", "primary"), ("draft", "Withdraw to Draft", "")],
        "scheduled": [("implemented", "Mark Implemented", "ok"), ("approved", "Unschedule", "")],
        "implemented": [("closed", "Close", "primary")],
        "rejected": [("draft", "Revise as Draft", "")],
        "closed": [],
    },
    "request": {
        "new": [("in_progress", "Start Work", "primary"), ("fulfilled", "Fulfil", "ok")],
        "in_progress": [("fulfilled", "Fulfil", "ok")],
        "fulfilled": [("closed", "Close", "primary"), ("in_progress", "Reopen", "danger")],
        "closed": [],
    },
}

# The resolution clock has stopped in these states ("done"); everything else is open/active.
DONE = {"resolved", "closed", "fulfilled", "implemented", "rejected"}
# Reaching one of these sets resolved_at.
RESOLVING = {"resolved", "fulfilled", "implemented"}
# Final states (closed_at set).
FINAL = {"closed", "rejected"}
# Kinds that carry response/resolution SLAs.
SLA_KINDS = {"incident", "request"}

# Display tone of each status (matches the pill styles in page.css) and donut colour.
STATUS_TONE = {
    "new": "crit", "acknowledged": "info", "investigating": "warn", "mitigated": "purple", "known_error": "purple",
    "resolved": "ok", "closed": "mute", "draft": "mute", "submitted": "warn", "approved": "ok", "scheduled": "info",
    "implemented": "ok", "rejected": "crit", "in_progress": "warn", "fulfilled": "ok",
}
STATUS_COLOR = {
    "new": "#d92d20", "acknowledged": "#2b4cff", "investigating": "#e08a00", "mitigated": "#7a4fd6",
    "known_error": "#7a4fd6", "resolved": "#0f7a55", "closed": "#a8a398", "draft": "#d6cfc1", "submitted": "#e08a00",
    "approved": "#0e8a7a", "scheduled": "#2b4cff", "implemented": "#0f7a55", "rejected": "#d92d20",
    "in_progress": "#e08a00", "fulfilled": "#0f7a55",
}
PRIORITY_TONE = {"P1": "crit", "P2": "crit", "P3": "warn", "P4": "ok"}
PRIORITY_DOT = {"P1": True, "P2": False, "P3": True, "P4": False}


def statuses_for(kind):
    """(value, label) choices valid for a kind, in workflow order."""
    return [(s, STATUS_LABELS[s]) for s in FLOW[kind]]


def transitions(kind, status):
    return TRANSITIONS.get(kind, {}).get(status, [])


def allowed(kind, status, target):
    return any(t == target for t, _, _ in transitions(kind, status))


def is_reopen(status, target):
    return status in DONE and target not in DONE


def approval_state(status):
    """Change approval state derived from the change status."""
    if status in ("draft",):
        return "not_submitted"
    if status == "submitted":
        return "pending"
    if status == "rejected":
        return "rejected"
    return "approved"


APPROVAL_LABELS = {"not_submitted": "Not submitted", "pending": "Pending approval", "approved": "Approved", "rejected": "Rejected"}
APPROVAL_TONE = {"not_submitted": "mute", "pending": "warn", "approved": "ok", "rejected": "crit"}
