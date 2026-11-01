"""Template helpers for the Domains pages (`{% load dm %}`)."""
from django import template
from django.utils.html import format_html

from core.templatetags.le import icon

from ..analytics import fmt_duration

register = template.Library()

GRADE_TONES = {"A": "ok", "B": "ok", "C": "warn", "D": "warn", "E": "crit", "F": "crit"}


@register.filter
def uptime_tone(value):
    """CSS text tone for an uptime percentage (None = no data)."""
    if value is None:
        return "t-mute"
    if value < 99:
        return "t-crit"
    if value < 99.9:
        return "t-warn"
    return "t-ok"


@register.filter
def cell_tone(value):
    """Daily availability cell colour class."""
    if value is None:
        return "nd"
    if value >= 99.9:
        return "ok"
    if value >= 99:
        return "ok2"
    if value >= 95:
        return "warn"
    return "crit"


@register.filter
def duration(td):
    return fmt_duration(td)


@register.filter
def grade_tone(grade):
    return GRADE_TONES.get(grade or "", "mute")


@register.simple_tag
def grade_chip(grade, big=False):
    if not grade:
        return format_html('<span class="dm-grade mute{}" title="Not graded">–</span>', " big" if big else "")
    return format_html('<span class="dm-grade {}{}" title="Security grade {}">{}</span>', GRADE_TONES.get(grade, "mute"),
                       " big" if big else "", grade, grade)


@register.simple_tag
def passfail(finding):
    """Pass / fail glyph for one security finding dict (None = not scanned)."""
    if not finding:
        return format_html('<span class="dm-pf nd" title="Not scanned">–</span>')
    ok = finding.get("passed")
    return format_html('<span class="dm-pf {}" title="{}: {}">{}</span>', "ok" if ok else "bad",
                       finding.get("label", ""), finding.get("detail", ""), icon("check" if ok else "x", 13))


@register.filter
def signed(value):
    if value is None:
        return "–"
    return f"{value:+.1f}%"


@register.filter
def ticks(text):
    """Escape text and render `backticked` fragments as <code>."""
    import re

    from django.utils.html import escape
    from django.utils.safestring import mark_safe
    return mark_safe(re.sub(r"`([^`]+)`", r"<code>\1</code>", escape(text or "")))
