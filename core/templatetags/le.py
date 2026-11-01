from django import template
from django.utils import timezone
from django.utils.html import format_html
from django.utils.safestring import mark_safe

register = template.Library()

# Stroke icons (24x24 viewBox), drawn for LinkedEye.
ICONS = {
    "home": '<path d="M3 11l9-7 9 7"/><path d="M5 10v10h14V10"/><path d="M10 20v-6h4v6"/>',
    "headset": '<path d="M4 14v-2a8 8 0 0116 0v2"/><rect x="3" y="14" width="4" height="6" rx="1.5"/><rect x="17" y="14" width="4" height="6" rx="1.5"/>',
    "box": '<path d="M3 7l9-4 9 4-9 4-9-4z"/><path d="M3 7v10l9 4 9-4V7"/><path d="M12 11v10"/>',
    "database": '<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
    "activity": '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
    "network": '<rect x="9" y="3" width="6" height="5" rx="1"/><rect x="2" y="16" width="6" height="5" rx="1"/><rect x="16" y="16" width="6" height="5" rx="1"/><path d="M12 8v4M5 16v-4h14v4"/>',
    "globe": '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3c2.5 2.7 3.8 5.7 3.8 9s-1.3 6.3-3.8 9c-2.5-2.7-3.8-5.7-3.8-9S9.5 5.7 12 3z"/>',
    "link": '<path d="M10 14a4.5 4.5 0 006.4 0l3-3a4.5 4.5 0 00-6.4-6.4l-1 1"/><path d="M14 10a4.5 4.5 0 00-6.4 0l-3 3a4.5 4.5 0 006.4 6.4l1-1"/>',
    "calendar": '<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M3 10h18M8 3v4M16 3v4"/><path d="M9 15l2 2 4-4"/>',
    "zap": '<path d="M13 2L4 14h7l-1 8 9-12h-7l1-8z"/>',
    "clipboard": '<rect x="5" y="4" width="14" height="17" rx="2"/><path d="M9 4V3h6v1M9 10h6M9 14h6M9 18h4"/>',
    "settings": '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 00.3 1.8l.1.1a2 2 0 11-2.8 2.8l-.1-.1a1.7 1.7 0 00-1.8-.3 1.7 1.7 0 00-1 1.5V21a2 2 0 11-4 0v-.1a1.7 1.7 0 00-1.1-1.5 1.7 1.7 0 00-1.8.3l-.1.1a2 2 0 11-2.8-2.8l.1-.1a1.7 1.7 0 00.3-1.8 1.7 1.7 0 00-1.5-1H3a2 2 0 110-4h.1a1.7 1.7 0 001.5-1.1 1.7 1.7 0 00-.3-1.8l-.1-.1a2 2 0 112.8-2.8l.1.1a1.7 1.7 0 001.8.3H9a1.7 1.7 0 001-1.5V3a2 2 0 114 0v.1a1.7 1.7 0 001 1.5 1.7 1.7 0 001.8-.3l.1-.1a2 2 0 112.8 2.8l-.1.1a1.7 1.7 0 00-.3 1.8V9a1.7 1.7 0 001.5 1H21a2 2 0 110 4h-.1a1.7 1.7 0 00-1.5 1z"/>',
    "search": '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>',
    "bell": '<path d="M6 8a6 6 0 0112 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.9 1.9 0 003.4 0"/>',
    "help": '<circle cx="12" cy="12" r="9"/><path d="M9.1 9a3 3 0 015.8 1c0 2-3 3-3 3"/><path d="M12 17h.01"/>',
    "chevron-down": '<path d="M6 9l6 6 6-6"/>',
    "chevron-right": '<path d="M9 6l6 6-6 6"/>',
    "chevron-left": '<path d="M15 6l-6 6 6 6"/>',
    "plus": '<path d="M12 5v14M5 12h14"/>',
    "download": '<path d="M12 3v12M7 10l5 5 5-5"/><path d="M5 21h14"/>',
    "refresh": '<path d="M20 11a8 8 0 00-14.9-3.9L4 9"/><path d="M4 4v5h5"/><path d="M4 13a8 8 0 0014.9 3.9L20 15"/><path d="M20 20v-5h-5"/>',
    "play": '<path d="M7 4l13 8-13 8V4z"/>',
    "edit": '<path d="M4 20h4L19 9l-4-4L4 16v4z"/><path d="M13.5 6.5l4 4"/>',
    "trash": '<path d="M4 7h16M10 11v6M14 11v6"/><path d="M6 7l1 13h10l1-13M9 7V4h6v3"/>',
    "eye": '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
    "more": '<circle cx="5" cy="12" r="1.3"/><circle cx="12" cy="12" r="1.3"/><circle cx="19" cy="12" r="1.3"/>',
    "check": '<path d="M5 12l5 5 9-10"/>',
    "check-circle": '<circle cx="12" cy="12" r="9"/><path d="M8 12l3 3 5-6"/>',
    "x-circle": '<circle cx="12" cy="12" r="9"/><path d="M9 9l6 6M15 9l-6 6"/>',
    "alert": '<path d="M12 3l10 18H2L12 3z"/><path d="M12 10v5M12 18h.01"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    "shield": '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6l8-3z"/>',
    "lock": '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/>',
    "server": '<rect x="3" y="4" width="18" height="7" rx="1.5"/><rect x="3" y="13" width="18" height="7" rx="1.5"/><path d="M7 7.5h.01M7 16.5h.01"/>',
    "cpu": '<rect x="6" y="6" width="12" height="12" rx="2"/><rect x="9.5" y="9.5" width="5" height="5"/><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"/>',
    "file": '<path d="M14 3H7a2 2 0 00-2 2v14a2 2 0 002 2h10a2 2 0 002-2V8l-5-5z"/><path d="M14 3v5h5M9 13h6M9 17h6"/>',
    "pause": '<path d="M9 5v14M15 5v14"/>',
    "filter": '<path d="M3 5h18l-7 8v6l-4 2v-8L3 5z"/>',
    "bar": '<path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/>',
    "flame": '<path d="M12 22c4 0 7-2.7 7-7 0-4-3-6-4-10-2 2-3 4-3 6-1-1-2-2-2-4-2 2-5 5-5 8 0 4.3 3 7 7 7z"/>',
    "info": '<circle cx="12" cy="12" r="9"/><path d="M12 11v6M12 7.5h.01"/>',
    "users": '<circle cx="9" cy="8" r="3.5"/><path d="M2 20c0-3.6 3.1-6 7-6s7 2.4 7 6"/><path d="M16 4.5a3.5 3.5 0 010 7M18 14c2.4.6 4 2.6 4 6"/>',
    "key": '<circle cx="7.5" cy="15.5" r="4.5"/><path d="M10.7 12.3L20 3M16 7l3 3M14 9l2 2"/>',
    "menu": '<path d="M9 6h12M9 12h12M9 18h12M4 6h.01M4 12h.01M4 18h.01"/>',
    "template": '<rect x="4" y="3" width="16" height="18" rx="2"/><path d="M8 8h8M8 12h8M8 16h5"/>',
    "exporters": '<path d="M4 20V10M9 20V6M14 20v-8M20 4l-4 4M20 4h-4M20 4v4"/>',
    "logs": '<path d="M4 20V12M9 20V8M14 20V4M19 20v-6M3 20h18"/>',
    "analytics": '<rect x="3" y="3" width="18" height="18" rx="2"/><path d="M8 16v-4M12 16V8M16 16v-6"/>',
    "browser": '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18M6.5 6.5h.01M9 6.5h.01"/>',
    "gauge": '<circle cx="12" cy="12" r="9"/><path d="M12 12l4-4M7 15h.01M12 7h.01M17 15h.01"/>',
    "bot": '<rect x="5" y="8" width="14" height="11" rx="2"/><path d="M12 4v4M9 13h.01M15 13h.01M9 17h6"/>',
    "user": '<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 3.6-7 8-7s8 3 8 7"/>',
    "alarm": '<circle cx="12" cy="13" r="7"/><path d="M12 10v3l2 2M5 4L2 7M19 4l3 3"/>',
    "arrow-up": '<path d="M12 19V5M6 11l6-6 6 6"/>',
    "arrow-down": '<path d="M12 5v14M6 13l6 6 6-6"/>',
    "arrow-right": '<path d="M5 12h14M13 6l6 6-6 6"/>',
    "upload": '<path d="M12 21V9M7 14l5-5 5 5"/><path d="M5 3h14"/>',
    "book": '<path d="M4 4h6a3 3 0 013 3v13a2 2 0 00-2-2H4V4z"/><path d="M20 4h-6a3 3 0 00-3 3v13a2 2 0 012-2h7V4z"/>',
    "grid": '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
    "wifi": '<path d="M2 9a15 15 0 0120 0M5 12.5a10 10 0 0114 0M8.5 16a5 5 0 017 0M12 19.5h.01"/>',
    "hdd": '<rect x="3" y="12" width="18" height="8" rx="2"/><path d="M5 12l2.5-7h9l2.5 7M7 16h.01M11 16h.01"/>',
    "hexagon": '<path d="M12 2l8.7 5v10L12 22l-8.7-5V7L12 2z"/><circle cx="12" cy="12" r="3"/>',
    "brick": '<rect x="3" y="4" width="18" height="16" rx="1"/><path d="M3 9.3h18M3 14.6h18M9 4v5.3M15 9.3v5.3M9 14.6V20"/>',
    "layers": '<path d="M12 3l9 5-9 5-9-5 9-5z"/><path d="M3 13l9 5 9-5"/>',
    "app": '<rect x="3" y="3" width="18" height="18" rx="3"/><path d="M8 9h8M8 13h5"/>',
    "external": '<path d="M14 4h6v6M20 4l-9 9"/><path d="M18 14v5a1 1 0 01-1 1H5a1 1 0 01-1-1V7a1 1 0 011-1h5"/>',
    "radar": '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><path d="M12 12l6-6"/>',
    "share": '<circle cx="6" cy="12" r="2.5"/><circle cx="18" cy="6" r="2.5"/><circle cx="18" cy="18" r="2.5"/><path d="M8.2 10.9l7.6-3.8M8.2 13.1l7.6 3.8"/>',
    "terminal": '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3M13 15h4"/>',
    "code": '<path d="M8 7l-5 5 5 5M16 7l5 5-5 5M14 4l-4 16"/>',
    "tag": '<path d="M3 12V4a1 1 0 011-1h8l9 9-9 9-9-9z"/><circle cx="7.5" cy="7.5" r="1.3"/>',
    "sort": '<path d="M8 4v16M4 8l4-4 4 4M16 20V4M12 16l4 4 4-4"/>',
    "sun": '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
    "mail": '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/>',
    "award": '<circle cx="12" cy="9" r="6"/><path d="M8.5 14L7 22l5-3 5 3-1.5-8"/>',
    "file-search": '<path d="M14 3H7a2 2 0 00-2 2v14a2 2 0 002 2h4"/><path d="M14 3v5h5v3"/><circle cx="16.5" cy="16.5" r="3"/><path d="M21 21l-2.3-2.3"/>',
    "heartbeat": '<path d="M3 12h4l2-5 4 10 2-5h6"/>',
    "list": '<path d="M9 6h12M9 12h12M9 18h12M4 6h.01M4 12h.01M4 18h.01"/>',
    "x": '<path d="M6 6l12 12M18 6L6 18"/>',
    "expand": '<path d="M4 9V4h5M20 9V4h-5M4 15v5h5M20 15v5h-5"/>',
    "sliders": '<path d="M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12M20 18h0"/><circle cx="16" cy="6" r="2"/><circle cx="10" cy="12" r="2"/><circle cx="18" cy="18" r="2"/>',
    "memory": '<rect x="3" y="7" width="18" height="10" rx="1"/><path d="M7 7v10M11 7v10M15 7v10M5 20v-3M19 20v-3"/>',
    "shield-alert": '<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6l8-3z"/><path d="M12 8v4M12 15.5h.01"/>',
    "file-check": '<path d="M14 3H7a2 2 0 00-2 2v14a2 2 0 002 2h10a2 2 0 002-2V8l-5-5z"/><path d="M14 3v5h5M9 14l2 2 4-4"/>',
    "users-cog": '<circle cx="9" cy="8" r="3.5"/><path d="M2 20c0-3.6 3.1-6 7-6 1.4 0 2.6.3 3.7.8"/><circle cx="18" cy="17" r="2.5"/><path d="M18 13v1.5M18 19.5V21M14 17h1.5M20.5 17H22"/>',
    "cloud": '<path d="M7 18a4.5 4.5 0 01-.6-9A6 6 0 0118 9a4 4 0 01-1 9H7z"/>',
    "plug": '<path d="M9 2v6M15 2v6M6 8h12v4a6 6 0 01-12 0V8zM12 18v4"/>',
    "calendar-range": '<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M3 10h18M8 3v4M16 3v4M7 14h4M13 17h4"/>',
    "logout": '<path d="M15 4h4a1 1 0 011 1v14a1 1 0 01-1 1h-4M10 17l-5-5 5-5M5 12h12"/>',
}


@register.simple_tag
def icon(name, size=18, cls=""):
    body = ICONS.get(name, ICONS["info"])
    return mark_safe(
        f'<svg class="ic {cls}" width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        f'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{body}</svg>'
    )


# status word -> (css tone, icon)
TONES = {
    "online": ("ok", "check-circle"), "up": ("ok", "check-circle"), "valid": ("ok", "check-circle"),
    "resolved": ("ok", "check-circle"), "ok": ("ok", "check-circle"), "active": ("ok", "check-circle"),
    "healthy": ("ok", "check-circle"), "met": ("ok", "check-circle"),
    "degraded": ("warn", "alert"), "expiring": ("warn", "alert"), "warning": ("warn", "alert"),
    "warn": ("warn", "alert"), "in progress": ("warn", "clock"), "medium": ("warn", "alert"), "high": ("crit", "alert"),
    "down": ("crit", "x-circle"), "failed": ("crit", "x-circle"), "expired": ("crit", "x-circle"),
    "invalid": ("crit", "x-circle"), "error": ("crit", "x-circle"), "critical": ("crit", "x-circle"),
    "inactive": ("mute", "pause"), "unreachable": ("crit", "x-circle"), "open": ("crit", "info"),
    "unknown": ("mute", "help"), "paused": ("mute", "pause"), "closed": ("mute", "check"), "low": ("ok", "info"),
    "info": ("info", "info"),
}


FILLED = {
    "check-circle": '<circle cx="12" cy="12" r="10" fill="currentColor" stroke="none"/><path d="M7.5 12.2l3 3 6-6.4" stroke="#fff" stroke-width="2.4"/>',
    "x-circle": '<circle cx="12" cy="12" r="10" fill="currentColor" stroke="none"/><path d="M8.5 8.5l7 7M15.5 8.5l-7 7" stroke="#fff" stroke-width="2.4"/>',
    "alert": '<path d="M12 2.5l10 18H2l10-18z" fill="currentColor" stroke="none"/><path d="M12 9.5v5M12 17.3h.01" stroke="#fff" stroke-width="2.4"/>',
    "clock": '<circle cx="12" cy="12" r="10" fill="currentColor" stroke="none"/><path d="M12 7v5l3 2" stroke="#fff" stroke-width="2.2"/>',
    "info": '<circle cx="12" cy="12" r="10" fill="currentColor" stroke="none"/><path d="M12 11v6M12 7.5h.01" stroke="#fff" stroke-width="2.4"/>',
    "pause": '<circle cx="12" cy="12" r="10" fill="currentColor" stroke="none"/><path d="M10 8.5v7M14 8.5v7" stroke="#fff" stroke-width="2.4"/>',
    "help": '<circle cx="12" cy="12" r="10" fill="currentColor" stroke="none"/><path d="M9.3 9.4a2.8 2.8 0 015.4 1c0 1.8-2.7 2.3-2.7 3.6M12 17.2h.01" stroke="#fff" stroke-width="2.1"/>',
    "check": '<circle cx="12" cy="12" r="10" fill="currentColor" stroke="none"/><path d="M7.5 12.2l3 3 6-6.4" stroke="#fff" stroke-width="2.4"/>',
}


@register.simple_tag
def ficon(name, size=14, cls=""):
    """Filled status glyph (solid circle/triangle with a white mark)."""
    body = FILLED.get(name, FILLED["info"])
    return mark_safe(
        f'<svg class="ic {cls}" width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
        f'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{body}</svg>'
    )


@register.simple_tag
def badge(status, label=None):
    key = str(status or "unknown").lower()
    tone, ic = TONES.get(key, ("mute", "help"))
    text = label or str(status or "Unknown").replace("_", " ").title()
    return format_html('<span class="badge {}">{}{}</span>', tone, ficon(ic, 14), text)


@register.simple_tag
def delta(value, good="up", suffix="%"):
    """Trend pill: arrow + value; green when the change goes in the `good` direction."""
    if value is None:
        return ""
    v = float(value)
    up = v >= 0
    tone = "t-ok" if (up and good == "up") or (not up and good == "down") else "t-crit"
    return format_html('<span class="delta {}">{}{}{}</span>', tone, icon("arrow-up" if up else "arrow-down", 12),
                       f"{abs(v):g}", suffix)


@register.filter
def ms(value):
    if value is None or value == "":
        return "–"
    return f"{float(value):,.0f} ms"


@register.filter
def pct(value, digits=2):
    if value is None:
        return "–"
    return f"{value:.{digits}f}%"


@register.filter
def short_dt(value):
    if not value:
        return "Never"
    return timezone.localtime(value).strftime("%d %b %H:%M")


@register.filter
def ago(value):
    if not value:
        return "never"
    s = int((timezone.now() - value).total_seconds())
    if s < 60:
        return f"{s}s ago"
    if s < 3600:
        return f"{s // 60} min ago"
    if s < 86400:
        return f"{s // 3600} h ago"
    return f"{s // 86400} d ago"


@register.filter
def tone(status):
    return TONES.get(str(status or "").lower(), ("mute", ""))[0]
