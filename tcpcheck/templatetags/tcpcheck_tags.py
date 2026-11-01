from django import template

from core.templatetags.le import ms

register = template.Library()


@register.filter
def connect_ms(value):
    """Like the kit's `ms`, but a sub-millisecond connect (LAN/loopback) reads "<1 ms" instead of "0 ms"."""
    if value is not None and value != "" and 0 <= float(value) < 0.5:
        return "<1 ms"
    return ms(value)
