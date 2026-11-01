"""Formatting filters for the network pages."""
from django import template

register = template.Library()


@register.filter
def mbps(value):
    """Traffic rate in Mbps with a sensible precision ('–' when unknown)."""
    if value is None or value == "":
        return "–"
    v = float(value)
    if v >= 1000:
        return f"{v / 1000:,.2f} Gbps"
    if v >= 100:
        return f"{v:,.0f} Mbps"
    if v >= 1:
        return f"{v:,.1f} Mbps"
    if v > 0:
        return f"{v * 1000:,.0f} kbps"
    return "0 Mbps"


@register.filter
def mbps_num(value):
    """Rate as a bare number of Mbps (for columns headed "(Mbps)")."""
    if value is None or value == "":
        return "–"
    v = float(value)
    if v == 0:
        return "0"
    if v < 0.01:
        return "<0.01"
    if v < 10:
        return f"{v:.2f}".rstrip("0").rstrip(".")
    if v < 100:
        return f"{v:.1f}".rstrip("0").rstrip(".")
    return f"{v:,.0f}"


@register.filter
def speed(value):
    """Interface speed (Mbps) as 100M / 1G / 10G."""
    if value is None or value == "":
        return "–"
    v = float(value)
    if v >= 1000:
        g = v / 1000
        return f"{g:g}G" if g == int(g) else f"{g:.1f}G"
    return f"{v:g}M"


@register.filter
def latency(value):
    if value is None or value == "":
        return "–"
    v = float(value)
    return f"{v:,.0f} ms" if v >= 10 else f"{v:.1f} ms"


@register.filter
def percent(value, digits=1):
    if value is None or value == "":
        return "–"
    return f"{float(value):.{int(digits)}f}%"


@register.filter
def avail_tone(value):
    if value is None:
        return "t-mute"
    return "t-ok" if value >= 99.5 else "t-warn" if value >= 95 else "t-crit"


@register.filter
def if_state(value):
    return {"up": "up", "down": "down", "lowerLayerDown": "down", "notPresent": "unknown", "dormant": "paused",
            "testing": "warning"}.get(value or "", "unknown")


@register.simple_tag
def sort_link(query, field, current, label):
    """Column header link that toggles ascending/descending sort, keeping the other filters."""
    from django.utils.html import format_html
    q = query.copy()
    desc = current == field
    q["sort"] = f"-{field}" if desc else field
    arrow = " ↑" if current == field else " ↓" if current == f"-{field}" else ""
    return format_html('<a class="sort" href="?{}">{}{}</a>', q.urlencode(), label, arrow)
