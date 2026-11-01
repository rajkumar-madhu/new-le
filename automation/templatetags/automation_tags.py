import json

from django import template
from django.utils.html import escape, format_html, format_html_join
from django.utils.safestring import mark_safe

from ..models import parse_steps

register = template.Library()


def _line(text):
    """One escaped line; shell commands ("$ …") and indented lines render as code."""
    stripped = text.strip()
    if stripped.startswith("$ ") or (text.startswith("    ") and stripped):
        return format_html('<code class="cmd">{}</code>', stripped)
    return escape(stripped)


@register.filter
def runbook_steps(text):
    """Render plain-text steps as a numbered list. All text is HTML-escaped."""
    steps = parse_steps(text)
    if not steps:
        return mark_safe('<p class="t-mute">No steps written yet.</p>')
    items = []
    for lines in steps:
        body = mark_safe("<br>".join(str(_line(ln)) for ln in lines if ln.strip()))
        items.append((body,))
    return format_html('<ol class="rb-steps">{}</ol>', format_html_join("", "<li><div>{}</div></li>", items))


@register.filter
def linebreaks_escaped(text):
    """Escape and keep line breaks (no paragraphs)."""
    lines = (text or "").replace("\r\n", "\n").split("\n")
    return mark_safe("<br>".join(str(escape(ln)) for ln in lines))


@register.filter
def pretty_json(value):
    try:
        return json.dumps(value, indent=2, sort_keys=True, default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(value)


@register.filter
def duration(ms):
    if ms is None:
        return "–"
    if ms < 1000:
        return f"{ms:,.0f} ms"
    return f"{ms / 1000:,.1f} s"


@register.filter
def minutes(value):
    """15 -> "15 min", 120 -> "2 h", 1440 -> "1 day", 0 -> "None"."""
    try:
        m = int(value or 0)
    except (TypeError, ValueError):
        return "–"
    if m <= 0:
        return "None"
    if m % 1440 == 0:
        d = m // 1440
        return f"{d} day{'s' if d != 1 else ''}"
    if m % 60 == 0:
        return f"{m // 60} h"
    return f"{m} min"


@register.filter
def get_item(d, key):
    try:
        return d.get(key)
    except AttributeError:
        return None
