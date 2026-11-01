"""Service desk presentation tags: priority/status pills, assignee avatars and SLA cells."""
from django import template
from django.utils import timezone
from django.utils.html import format_html

from core.templatetags.le import icon

from .. import sla as sla_mod
from .. import stats
from .. import workflow as wf

register = template.Library()


@register.simple_tag
def prio_pill(priority, short=False):
    tone = wf.PRIORITY_TONE.get(priority, "mute")
    dot = format_html("<i></i>") if wf.PRIORITY_DOT.get(priority) else ""
    label = priority if short else wf.PRIORITY_LABELS.get(priority, priority)
    return format_html('<span class="ip {}" title="{} · {}">{}{}</span>', tone, priority,
                       wf.PRIORITY_LABELS.get(priority, ""), dot, label)


@register.simple_tag
def status_pill(status, large=False):
    tone = wf.STATUS_TONE.get(status, "mute")
    dot = format_html("<i></i>") if tone in ("warn", "ok", "mute", "purple", "info") else ""
    return format_html('<span class="ip {}{}">{}{}</span>', tone, " lg" if large else "", dot,
                       wf.STATUS_LABELS.get(status, status))


@register.simple_tag
def who(user, empty="Unassigned"):
    if user is None:
        return format_html('<span class="who t-mute"><span class="av sd-av none">{}</span>{}</span>', icon("user", 13), empty)
    name = user.get_full_name() or user.get_username()
    return format_html('<span class="who"><span class="av sd-av" style="background:{}">{}</span>{}</span>',
                       stats.avatar_color(user), stats.initials(user), name)


@register.simple_tag
def sla_cell(ticket):
    """Resolution countdown for open tickets, a check for tickets resolved in time, a dash when no SLA."""
    if ticket.resolution_due is None and ticket.response_due is None:
        return format_html('<span class="t-mute" title="No SLA for this ticket kind">–</span>')
    c = sla_mod.resolution_clock(ticket) if ticket.resolution_due else sla_mod.response_clock(ticket)
    if c["state"] == "met" and not ticket.breached:
        return format_html('<span class="tn-ok" title="Resolved within SLA">{} <span class="t-mute">—</span></span>', icon("check-circle", 15))
    if not ticket.is_open:
        which = " and ".join(w for w, flag in (("response", ticket.response_breached),
                                                ("resolution", ticket.resolution_breached or c["state"] == "breached")) if flag)
        return format_html('<span class="tn-crit" title="{} SLA breached">{} {}</span>', which.capitalize() or "SLA",
                           icon("x-circle", 15), "breached")
    tone = {"breached": "crit", "at_risk": "warn"}.get(c["state"], "ok")
    if ticket.breached and c["state"] != "breached":
        tone = "crit"
    title = f"{c['label']} · due {timezone.localtime(c['due']):%d %b %H:%M}" if c["due"] else c["label"]
    return format_html('<span class="tn-{}" title="{}">{} {}</span>', tone, title, icon("clock", 15), c["text"])


@register.filter
def status_label(status):
    return wf.STATUS_LABELS.get(status, status)


@register.filter
def kind_label(kind):
    return wf.KIND_LABELS.get(kind, kind)


@register.filter
def get_item(mapping, key):
    try:
        return mapping.get(key)
    except AttributeError:
        return None
