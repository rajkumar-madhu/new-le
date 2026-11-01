"""Device, discovery and approval forms."""
from django import forms
from django.conf import settings
from django.core.exceptions import ValidationError

from . import discovery
from .models import Device, DeviceType, Environment

TEXT = {"class": "in"}


def site_choices(current="", blank_label="(No site)"):
    """Site names from core.Site plus any value already used by a device."""
    from core.models import Site
    t = settings.LINKEDEYE_TENANT
    names = set(Site.objects.filter(tenant_key=t).values_list("name", flat=True))
    names |= set(Device.objects.filter(tenant_key=t).order_by().values_list("site", flat=True).distinct())
    if current:
        names.add(current)
    names.discard("")
    ordered = sorted(names - {"All Sites"}, key=str.lower)
    return [("", blank_label)] + ([("All Sites", "All Sites")] if "All Sites" in names else []) + [(n, n) for n in ordered]


def normalise_tags(text):
    seen = []
    for t in (text or "").split(","):
        t = t.strip()
        if t and t.lower() not in [s.lower() for s in seen]:
            seen.append(t)
    return ", ".join(seen)


class DeviceForm(forms.ModelForm):
    site = forms.ChoiceField(required=False)

    GROUPS = [
        ("Identity", ["name", "device_type", "vendor", "model", "serial", "firmware"]),
        ("Monitoring", ["mgmt_ip", "check_port", "prometheus_instance", "enabled"]),
        ("Placement & ownership", ["site", "role", "environment", "contact"]),
        ("Notes", ["tags", "description"]),
    ]

    class Meta:
        model = Device
        fields = ["name", "device_type", "vendor", "model", "serial", "firmware", "mgmt_ip", "check_port",
                  "prometheus_instance", "enabled", "site", "role", "environment", "contact", "tags", "description"]
        widgets = {
            "description": forms.Textarea(attrs={"rows": 3}),
            "name": forms.TextInput(attrs={"placeholder": "e.g. core-sw-01", "autocomplete": "off"}),
            "mgmt_ip": forms.TextInput(attrs={"placeholder": "e.g. 10.10.1.254", "autocomplete": "off"}),
            "prometheus_instance": forms.TextInput(attrs={"placeholder": "e.g. 10.10.1.254"}),
            "tags": forms.TextInput(attrs={"placeholder": "e.g. core, dc1"}),
            "vendor": forms.TextInput(attrs={"placeholder": "e.g. Fortinet", "list": "net-vendors"}),
            "contact": forms.TextInput(attrs={"placeholder": "e.g. network@example.com"}),
            "role": forms.TextInput(attrs={"placeholder": "e.g. Perimeter Firewall"}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["site"].choices = site_choices(self.instance.site if self.instance.pk else self.initial.get("site", ""))
        self.fields["environment"].choices = [("", "—")] + list(Environment.choices)
        self.fields["check_port"].widget.attrs.update({"min": 1, "max": 65535})

    @property
    def groups(self):
        return [(title, [self[f] for f in names]) for title, names in self.GROUPS]

    def clean_name(self):
        name = self.cleaned_data["name"].strip()
        qs = Device.objects.filter(tenant_key=settings.LINKEDEYE_TENANT, name__iexact=name)
        if self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise ValidationError("A device with this name already exists.")
        return name

    def clean_mgmt_ip(self):
        return self.cleaned_data["mgmt_ip"].strip()

    def clean_prometheus_instance(self):
        return self.cleaned_data["prometheus_instance"].strip()

    def clean_tags(self):
        return normalise_tags(self.cleaned_data["tags"])


class DiscoveryForm(forms.Form):
    cidr = forms.CharField(label="Network (CIDR)", max_length=64,
                           widget=forms.TextInput(attrs={"placeholder": "e.g. 10.10.20.0/24", "autocomplete": "off"}),
                           help_text="IPv4 /24 or smaller (IPv6 /120). Only addresses the probe policy allows are contacted.")
    ports = forms.CharField(label="TCP ports", max_length=100, initial="22,443",
                            widget=forms.TextInput(attrs={"placeholder": "22,443"}),
                            help_text=f"Comma-separated, at most {discovery.MAX_PORTS}. A host is listed when any port answers.")
    site = forms.ChoiceField(label="Site for approved devices", required=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["site"].choices = site_choices(self.initial.get("site", ""))

    def clean_cidr(self):
        net = discovery.parse_cidr(self.cleaned_data["cidr"])
        allowed, _blocked = discovery.split_allowed(discovery.addresses(net))
        if not allowed:
            raise ValidationError("No address in this network is allowed by the probe policy. Private ranges must be listed in "
                                  "LINKEDEYE_PROBE_ALLOWED_PRIVATE_CIDRS; link-local, multicast and reserved ranges are never scanned.")
        return str(net)

    def clean_ports(self):
        return ",".join(str(p) for p in discovery.parse_ports(self.cleaned_data["ports"]))


class ApproveForm(forms.Form):
    device_type = forms.ChoiceField(label="Device type", choices=DeviceType.choices)
    site = forms.ChoiceField(required=False)
    name_prefix = forms.CharField(label="Name prefix", max_length=60, required=False,
                                  widget=forms.TextInput(attrs={"placeholder": "e.g. sw-"}),
                                  help_text="Devices are named prefix + IP address; rename them later.")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["site"].choices = site_choices(self.initial.get("site", ""))
