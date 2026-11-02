from django import template
from django.utils.html import format_html

from .. import fmt
from ..hosts import HEALTH_LABEL, HEALTH_TONE, grade as _grade
from ..models import severity_tone
from ..nagios import STATE_TONE

register = template.Library()


@register.filter
def since(value):
    """Like core's |ago, but clock skew between LinkedEye and the source never shows a negative age."""
    if not value:
        return "never"
    from django.utils import timezone
    s = int((timezone.now() - value).total_seconds())
    if s < 5:
        return "just now"
    if s < 60:
        return f"{s}s ago"
    if s < 3600:
        return f"{s // 60} min ago"
    if s < 86400:
        return f"{s // 3600} h ago"
    return f"{s // 86400} d ago"


@register.filter
def nagios_label(state):
    return {"ok": "OK", "up": "Up"}.get(state, str(state or "unknown").title())


@register.filter
def hbytes(v):
    return fmt.human_bytes(v)


@register.filter
def hrate(v):
    return fmt.human_rate(v)


@register.filter
def hduration(v):
    return fmt.human_duration(v)


@register.filter
def hnum(v):
    return fmt.human_number(v)


@register.filter
def pct1(v):
    return "–" if not fmt.finite(v) else f"{v:.1f}%"


@register.filter
def ms_from_s(v):
    return "–" if not fmt.finite(v) else (f"{v * 1000:.0f} ms" if v < 10 else f"{v:.1f} s")


@register.filter
def unit_small(text):
    """'915 ms' -> '915<small> ms</small>' so a KPI number keeps the large serif and its unit stays quiet."""
    s = str(text if text is not None else "")
    num, sep, rest = s.partition(" ")
    if not sep or not num[:1].isdigit():
        return s
    return format_html("{}<small> {}</small>", num, rest)


@register.filter
def health_label(h):
    return HEALTH_LABEL.get(h, "Unknown")


@register.filter
def health_tone(h):
    return HEALTH_TONE.get(h, "mute")


@register.filter
def sev_tone(s):
    return severity_tone(s)


@register.filter
def nagios_tone(state):
    return STATE_TONE.get(state, "mute")


@register.simple_tag
def grade(metric, value):
    return _grade(metric, value)


@register.filter
def clamp100(v):
    if not fmt.finite(v):
        return 0
    return max(0, min(100, round(v, 1)))


@register.filter
def from_unix(v):
    return fmt.from_epoch(v)


@register.filter
def safe_http(url):
    """Only http(s) URLs may become links (Alertmanager payloads are untrusted)."""
    u = str(url or "")
    return u if u.lower().startswith(("http://", "https://")) else ""
