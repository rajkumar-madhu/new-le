import ipaddress
import re
from decimal import Decimal

from django import forms
from django.conf import settings

from probes import checks

from .models import SlaTarget, TcpCheck

HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9_-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9_-]{1,63}(?<!-))*\.?$")

# Well-known ports offered as quick picks next to the port field.
COMMON_PORTS = [(22, "SSH"), (23, "Telnet"), (25, "SMTP"), (53, "DNS"), (80, "HTTP"), (110, "POP3"), (143, "IMAP"),
                (389, "LDAP"), (443, "HTTPS"), (445, "SMB"), (587, "SMTP submission"), (636, "LDAPS"),
                (1433, "SQL Server"), (1521, "Oracle"), (3306, "MySQL"), (3389, "RDP"), (5432, "PostgreSQL"),
                (5672, "AMQP"), (6379, "Redis"), (8080, "HTTP alt"), (8443, "HTTPS alt"), (9092, "Kafka"),
                (27017, "MongoDB")]

MAIN_FIELDS = ["name", "host", "port", "interval_seconds", "site", "tags"]
ADVANCED_FIELDS = ["expect_banner", "degraded_ms", "timeout_seconds", "description"]


def clean_host_value(host):
    host = (host or "").strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host:
        raise forms.ValidationError("Enter a hostname or IP address.")
    if "://" in host or "/" in host or " " in host:
        raise forms.ValidationError("Enter only a hostname or IP address – no scheme, path or spaces.")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        try:
            checks.check_address(str(ip))
        except checks.ProbeBlocked as e:
            raise forms.ValidationError(f"This address is not allowed by the probe policy: {e}.")
        return str(ip)
    if ":" in host:
        raise forms.ValidationError("Put the port in the Port field, not in the host.")
    if not HOST_RE.match(host):
        raise forms.ValidationError("Enter a valid hostname or IP address.")
    return host.rstrip(".").lower()


class TcpCheckForm(forms.ModelForm):
    class Meta:
        model = TcpCheck
        fields = ["name", "host", "port", "interval_seconds", "site", "tags", "expect_banner", "degraded_ms",
                  "timeout_seconds", "description", "enabled"]
        widgets = {
            "name": forms.TextInput(attrs={"placeholder": "e.g. Core DB listener"}),
            "host": forms.TextInput(attrs={"placeholder": "db01.example.com or 10.0.0.5", "autocapitalize": "off",
                                           "spellcheck": "false"}),
            "port": forms.NumberInput(attrs={"placeholder": "e.g. 22", "min": 1, "max": 65535, "list": "tcp-ports"}),
            "site": forms.TextInput(attrs={"placeholder": "All Sites", "list": "tcp-sites"}),
            "tags": forms.TextInput(attrs={"placeholder": "e.g. database, production"}),
            "expect_banner": forms.TextInput(attrs={"placeholder": "Optional, e.g. SSH- or 220"}),
            "description": forms.TextInput(attrs={"placeholder": "Optional"}),
            "degraded_ms": forms.NumberInput(attrs={"min": 1, "max": 60000}),
            "timeout_seconds": forms.NumberInput(attrs={"min": 1, "max": 30}),
        }
        labels = {"host": "Host / IP", "interval_seconds": "Check Interval", "site": "Site / Location",
                  "tags": "Tags (comma separated)", "expect_banner": "Expected Banner",
                  "degraded_ms": "Degraded Above (ms)", "timeout_seconds": "Timeout (s)"}
        help_texts = {"expect_banner": "", "degraded_ms": "", "host": ""}

    def __init__(self, *args, tenant=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.tenant = tenant or settings.LINKEDEYE_TENANT
        self.fields["site"].required = False

    def main_fields(self):
        return [self[n] for n in MAIN_FIELDS]

    def advanced_fields(self):
        return [self[n] for n in ADVANCED_FIELDS]

    def advanced_has_errors(self):
        return any(self[n].errors for n in ADVANCED_FIELDS + ["enabled"])

    def clean_name(self):
        name = self.cleaned_data["name"].strip()
        qs = TcpCheck.objects.filter(tenant_key=self.tenant, name__iexact=name)
        if self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise forms.ValidationError("A TCP check with this name already exists.")
        return name

    def clean_host(self):
        return clean_host_value(self.cleaned_data.get("host"))

    def clean_site(self):
        return (self.cleaned_data.get("site") or "").strip() or "All Sites"

    def clean_tags(self):
        tags = [t.strip() for t in (self.cleaned_data.get("tags") or "").split(",") if t.strip()]
        out = ", ".join(dict.fromkeys(tags))
        if len(out) > 200:
            raise forms.ValidationError("Tags are too long (200 characters at most).")
        return out

    def clean(self):
        data = super().clean()
        timeout, degraded = data.get("timeout_seconds"), data.get("degraded_ms")
        if timeout and degraded and degraded >= timeout * 1000:
            self.add_error("degraded_ms", "Must be lower than the timeout, otherwise a check can never be Degraded.")
        return data


class SlaForm(forms.Form):
    kind = forms.ChoiceField(choices=SlaTarget.KINDS)
    object_id = forms.IntegerField(min_value=1)
    target = forms.DecimalField(min_value=Decimal("50"), max_value=Decimal("100"), max_digits=6, decimal_places=3)
