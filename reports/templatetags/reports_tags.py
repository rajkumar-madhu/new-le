from django import template

register = template.Library()


@register.filter
def dur(minutes):
    """Minutes → '45m', '3h 20m', '2d 4h'. None → '–'."""
    if minutes is None or minutes == "":
        return "–"
    m = int(round(float(minutes)))
    if m < 60:
        return f"{m}m"
    h, m = divmod(m, 60)
    if h < 24:
        return f"{h}h {m}m" if m else f"{h}h"
    d, h = divmod(h, 24)
    return f"{d}d {h}h" if h else f"{d}d"


@register.filter
def share(n, total):
    """Percentage width (0-100) of n in total, for bar tracks."""
    try:
        return round(100.0 * float(n) / float(total), 1) if total else 0
    except (TypeError, ValueError):
        return 0


@register.filter
def get(d, key):
    return d.get(key, 0) if hasattr(d, "get") else 0
