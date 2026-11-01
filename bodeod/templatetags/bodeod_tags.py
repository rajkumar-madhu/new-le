from django import template
from django.utils import timezone
from django.utils.html import format_html

from bodeod.services import IST

register = template.Library()

CODE_META = {  # status -> (code, tone, short label)
    "ok": (0, "ok", "OK"), "signed_off": (0, "ok", "Signed off"), "warning": (1, "warn", "WARN"),
    "critical": (2, "crit", "CRIT"), "unknown": (3, "mute", "UNKNOWN"), "pending": (5, "info", "PENDING"),
    "disabled": ("–", "mute", "Disabled"),
}
RUN_META = {"pass": ("ok", "Pass"), "warn": ("warn", "Warning"), "fail": ("crit", "Fail"), "running": ("info", "Running")}


@register.filter
def ist(value, fmt="%d %b %Y %H:%M"):
    """Format an aware datetime in IST."""
    if not value:
        return "–"
    return timezone.localtime(value, IST).strftime(fmt)


@register.simple_tag
def code(status, show_label=True):
    """Status code pill: '0 OK', '2 CRIT', '5 PENDING' …"""
    num, tone, label = CODE_META.get(status, CODE_META["unknown"])
    if show_label:
        return format_html('<span class="bc bc-{}"><b>{}</b>{}</span>', tone, num, label)
    return format_html('<span class="bc bc-{}"><b>{}</b></span>', tone, num)


@register.filter
def code_tone(status):
    return CODE_META.get(status, CODE_META["unknown"])[1]


@register.filter
def code_num(status):
    return CODE_META.get(status, CODE_META["unknown"])[0]


@register.simple_tag
def run_badge(status):
    tone, label = RUN_META.get(status or "", ("mute", "No run"))
    icon = {"ok": "check-circle", "warn": "alert", "crit": "x-circle", "info": "clock"}.get(tone, "help")
    from core.templatetags.le import ficon
    return format_html('<span class="badge {}">{}{}</span>', tone, ficon(icon, 14), label)


@register.filter
def run_tone(status):
    return RUN_META.get(status or "", ("mute", ""))[0]
