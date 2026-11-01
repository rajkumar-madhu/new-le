from django import template

register = template.Library()


@register.filter
def compact(value):
    """12345 -> 12.3K, 1234567 -> 1.2M (whole numbers below 10,000 keep thousands separators)."""
    if value is None or value == "":
        return "–"
    v = float(value)
    a = abs(v)
    if a >= 1e9:
        s = f"{v / 1e9:.1f}B"
    elif a >= 1e6:
        s = f"{v / 1e6:.1f}M"
    elif a >= 1e4:
        s = f"{v / 1e3:.1f}K"
    else:
        return f"{int(round(v)):,}"
    return s.replace(".0", "")


@register.filter
def sev_icon(severity):
    return {"critical": "x-circle", "warning": "alert", "info": "info", "ok": "check-circle"}.get(severity, "info")


@register.filter
def sev_tone(severity):
    return {"critical": "crit", "warning": "warn", "info": "info", "ok": "ok"}.get(severity, "mute")
