"""Field specifications for record templates and the forms built from them.

A template stores default values (Template.fields) for one kind of record. The editor shows every field of the
kind as optional; the Apply page shows the same fields with the record's real requirements, pre-filled from the
template, so the operator confirms (and completes) the values before anything is created.
"""
from dataclasses import dataclass, field

from django import forms

PRIORITIES = [("P1", "P1 – Critical"), ("P2", "P2 – High"), ("P3", "P3 – Medium"), ("P4", "P4 – Low")]
SEVERITIES = [("critical", "Critical"), ("warning", "Warning"), ("info", "Info")]
URL_INTERVALS = [(60, "1 minute"), (120, "2 minutes"), (300, "5 minutes"), (600, "10 minutes"), (900, "15 minutes")]
TCP_INTERVALS = [(30, "30 seconds"), (60, "1 minute"), (120, "2 minutes"), (300, "5 minutes"), (600, "10 minutes"),
                 (900, "15 minutes")]


@dataclass
class Spec:
    key: str
    label: str
    type: str = "text"          # text | textarea | url | int | choice | intchoice | site
    required: bool = False
    choices: list = field(default_factory=list)
    default: object = None
    help: str = ""
    min: int = None
    max: int = None
    max_length: int = 200
    full: bool = False


SPECS = {
    "url_check": [
        Spec("name", "Check name", required=True, max_length=120, help="Must be unique among URL checks."),
        Spec("url", "URL", "url", required=True, max_length=2000, full=True),
        Spec("check_type", "Type", "choice", choices=[("web", "Web"), ("api", "API")], default="web"),
        Spec("method", "Method", "choice", choices=[("GET", "GET"), ("HEAD", "HEAD")], default="GET"),
        Spec("expected_status", "Expected status", "int", default=200, min=100, max=599),
        Spec("expected_text", "Expected text", help="Optional text the response body must contain."),
        Spec("interval_seconds", "Interval", "intchoice", choices=URL_INTERVALS, default=300),
        Spec("timeout_seconds", "Timeout (s)", "int", default=10, min=1, max=60),
        Spec("degraded_ms", "Degraded above (ms)", "int", default=1000, min=1, max=600000),
        Spec("site", "Site", "site", default="All Sites"),
        Spec("tags", "Tags", help="Comma separated."),
    ],
    "tcp_check": [
        Spec("name", "Check name", required=True, max_length=120, help="Must be unique among TCP checks."),
        Spec("host", "Host", required=True, max_length=253, help="Hostname or IP address."),
        Spec("port", "Port", "int", required=True, min=1, max=65535),
        Spec("interval_seconds", "Interval", "intchoice", choices=TCP_INTERVALS, default=60),
        Spec("timeout_seconds", "Timeout (s)", "int", default=5, min=1, max=30),
        Spec("degraded_ms", "Degraded above (ms)", "int", default=500, min=1, max=60000),
        Spec("expect_banner", "Expected banner", help="Optional text the server must send first (e.g. SSH-, 220)."),
        Spec("site", "Site", "site", default="All Sites"),
        Spec("tags", "Tags", help="Comma separated."),
        Spec("description", "Check description", max_length=300, full=True),
    ],
    "incident": [
        Spec("title", "Incident title", required=True, full=True),
        Spec("priority", "Priority", "choice", choices=PRIORITIES, default="P3"),
        Spec("site", "Site", "site", default=""),
        Spec("ci_name", "Configuration item", help="CMDB CI name, if known."),
        Spec("description", "Incident description", "textarea", max_length=5000, full=True),
    ],
    "notification": [
        Spec("title", "Event title", required=True, full=True),
        Spec("severity", "Severity", "choice", choices=SEVERITIES, default="warning",
             help="Critical and warning events are delivered by the notification channels."),
        Spec("site", "Site", "site", default=""),
        Spec("message", "Message", "textarea", max_length=5000, full=True),
    ],
}

KIND_HELP = {
    "url_check": "Creates a URL check in Monitoring › URL Checker. The scheduler runs it on its interval.",
    "tcp_check": "Creates a TCP check in Monitoring › Telnet Monitoring. The scheduler runs it on its interval.",
    "incident": "Opens an incident in the Service Desk.",
    "notification": "Emits an event into the unified event stream; critical and warning events go to the "
                    "configured notification channels (webhooks, e-mail).",
}

KIND_ICONS = {"url_check": "globe", "tcp_check": "terminal", "incident": "headset", "notification": "bell"}


def specs_for(kind):
    return SPECS.get(kind, [])


def _site_choices(sites, blank_label):
    names = [s for s in sites if s and s != "All Sites"]
    return [("", blank_label)] + [("All Sites", "All Sites")] + [(s, s) for s in names]


def build_field(spec, required, sites, initial=None, blank_site_label="Any / choose later"):
    attrs = {}
    common = {"label": spec.label, "required": required, "help_text": spec.help}
    if spec.type == "textarea":
        f = forms.CharField(max_length=spec.max_length, widget=forms.Textarea(attrs={"rows": 4}), **common)
    elif spec.type == "url":
        f = forms.URLField(max_length=spec.max_length, **common)
        attrs["placeholder"] = "https://"
    elif spec.type == "int":
        f = forms.IntegerField(min_value=spec.min, max_value=spec.max, **common)
    elif spec.type == "choice":
        choices = list(spec.choices) if required else [("", "–")] + list(spec.choices)
        f = forms.ChoiceField(choices=choices, **common)
    elif spec.type == "intchoice":
        choices = [(str(v), lbl) for v, lbl in spec.choices]
        f = forms.TypedChoiceField(choices=choices if required else [("", "–")] + choices, coerce=int,
                                   empty_value=None, **common)
    elif spec.type == "site":
        choices = _site_choices(sites, blank_site_label)
        f = forms.ChoiceField(choices=choices[1:] if required else choices, **common)
        if initial and initial not in dict(f.choices):
            f.choices = list(f.choices) + [(initial, initial)]
    else:
        f = forms.CharField(max_length=spec.max_length, **common)
    f.widget.attrs.update(attrs)
    f.spec = spec
    return f


class TemplateValuesMixin:
    kind = ""
    prefix_key = ""     # form field name = prefix_key + spec key (avoids clashes with the template's own fields)

    def spec_fields(self):
        return [self[self.prefix_key + s.key] for s in specs_for(self.kind) if self.prefix_key + s.key in self.fields]

    def values(self):
        """Cleaned values, without empty ones."""
        out = {}
        for s in specs_for(self.kind):
            v = self.cleaned_data.get(self.prefix_key + s.key)
            if v is None or v == "":
                continue
            out[s.key] = v
        return out


class ApplyForm(TemplateValuesMixin, forms.Form):
    """Confirmation form shown before a template creates its record."""

    def __init__(self, *args, kind, defaults=None, sites=(), **kwargs):
        super().__init__(*args, **kwargs)
        self.kind = kind
        defaults = defaults or {}
        for s in specs_for(kind):
            initial = defaults.get(s.key, s.default)
            f = build_field(s, s.required or s.key == "site" and kind in ("url_check", "tcp_check"), sites,
                            initial=initial, blank_site_label="No site")
            if initial is not None:
                f.initial = str(initial) if s.type == "intchoice" else initial
            self.fields[s.key] = f

    def values(self):
        out = super().values()
        if self.kind in ("url_check", "tcp_check"):
            out.setdefault("site", "All Sites")
        return out
