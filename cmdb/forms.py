"""Forms for configuration items, relationships, software, licenses and CSV import."""
import json

from django import forms
from django.conf import settings

from . import services
from .models import CIStatus, CIType, ConfigurationItem, Environment, License, Relationship, Software

MAX_IMPORT_BYTES = 2 * 1024 * 1024
MAX_IMPORT_ROWS = 5000


def site_choices(current=""):
    """Site names from core.Site plus any value already in use, with "All Sites" first."""
    from core.models import Site
    names = set(Site.objects.filter(tenant_key=settings.LINKEDEYE_TENANT).values_list("name", flat=True))
    names |= set(ConfigurationItem.objects.filter(tenant_key=settings.LINKEDEYE_TENANT)
                 .order_by().values_list("site", flat=True).distinct())
    if current:
        names.add(current)
    names -= {"", "All Sites"}
    return [("All Sites", "All Sites")] + [(n, n) for n in sorted(names, key=str.lower)]


class DateInput(forms.DateInput):
    input_type = "date"

    def __init__(self, attrs=None):
        super().__init__(attrs=attrs, format="%Y-%m-%d")


class AttributesField(forms.JSONField):
    """JSON object (key/value attributes). Empty input means {}."""

    def to_python(self, value):
        if value in (None, ""):
            return {}
        value = super().to_python(value)
        if not isinstance(value, dict):
            raise forms.ValidationError("Attributes must be a JSON object, e.g. {\"rack\": \"R12\"}.")
        return value

    def prepare_value(self, value):
        if value in (None, {}, ""):
            return ""
        if isinstance(value, str):
            return value
        return json.dumps(value, indent=2, sort_keys=True)


class CIForm(forms.ModelForm):
    site = forms.ChoiceField(label="Site", choices=())
    attributes = AttributesField(required=False, widget=forms.Textarea(attrs={"rows": 4, "placeholder": '{"rack": "R12", "os": "RHEL 9"}'}),
                                 help_text="Optional JSON object with extra attributes.")

    class Meta:
        model = ConfigurationItem
        fields = ["name", "ci_type", "status", "environment", "site", "owner", "business_domain", "description",
                  "ip_address", "vendor", "model", "serial", "asset_tag", "purchase_date", "warranty_end", "eol_date",
                  "cost", "prometheus_instance", "url_checks", "domains", "attributes"]
        widgets = {
            "name": forms.TextInput(attrs={"placeholder": "e.g. prod-oms-01"}),
            "owner": forms.TextInput(attrs={"placeholder": "Team or person"}),
            "business_domain": forms.TextInput(attrs={"placeholder": "e.g. Trading", "list": "cmdb-domains"}),
            "description": forms.Textarea(attrs={"rows": 3}),
            "ip_address": forms.TextInput(attrs={"placeholder": "10.10.1.21"}),
            "purchase_date": DateInput(), "warranty_end": DateInput(), "eol_date": DateInput(),
            "cost": forms.NumberInput(attrs={"step": "0.01", "min": "0"}),
            "prometheus_instance": forms.TextInput(attrs={"placeholder": "prod-oms-01:9100"}),
            "url_checks": forms.CheckboxSelectMultiple(),
            "domains": forms.CheckboxSelectMultiple(),
        }
        labels = {"ci_type": "Type", "ip_address": "IP Address", "url_checks": "Linked URL checks",
                  "domains": "Linked domains", "prometheus_instance": "Prometheus instance", "cost": "Cost"}

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user
        from domainmonitor.models import Domain
        from urlchecker.models import UrlCheck
        tenant = settings.LINKEDEYE_TENANT
        self.fields["url_checks"].queryset = UrlCheck.objects.filter(tenant_key=tenant).order_by("name")
        self.fields["domains"].queryset = Domain.objects.filter(tenant_key=tenant).order_by("hostname")
        self.fields["site"].choices = site_choices(self.instance.site if self.instance and self.instance.pk else "")
        self.fields["site"].initial = self.instance.site if self.instance and self.instance.pk else "All Sites"

    def clean_name(self):
        name = (self.cleaned_data.get("name") or "").strip()
        if not name:
            raise forms.ValidationError("Name is required.")
        qs = ConfigurationItem.objects.filter(tenant_key=settings.LINKEDEYE_TENANT, name__iexact=name)
        if self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise forms.ValidationError("A configuration item with this name already exists.")
        return name

    def clean_site(self):
        site = self.cleaned_data.get("site") or "All Sites"
        if self.user is not None and not services.can_manage(self.user, "operate", site):
            raise forms.ValidationError("You cannot manage items on this site.")
        return site

    def clean_prometheus_instance(self):
        v = (self.cleaned_data.get("prometheus_instance") or "").strip()
        if any(c in v for c in '"{}\\\n'):
            raise forms.ValidationError("Use the plain instance label, e.g. host:9100.")
        return v

    def clean(self):
        data = super().clean()
        p, w, e = data.get("purchase_date"), data.get("warranty_end"), data.get("eol_date")
        if p and w and w < p:
            self.add_error("warranty_end", "Warranty cannot end before the purchase date.")
        if p and e and e < p:
            self.add_error("eol_date", "End of life cannot be before the purchase date.")
        return data

    def save(self, commit=True):
        obj = super().save(commit=False)
        if not obj.tenant_key:
            obj.tenant_key = settings.LINKEDEYE_TENANT
        if commit:
            obj.save()
            self.save_m2m()
        return obj

    # field groups for the template
    GROUPS = [
        ("General", ["name", "ci_type", "status", "environment", "site", "owner", "business_domain", "description"]),
        ("Asset", ["ip_address", "vendor", "model", "serial", "asset_tag", "purchase_date", "warranty_end", "eol_date", "cost"]),
        ("Monitoring", ["url_checks", "domains", "prometheus_instance", "attributes"]),
    ]

    def groups(self):
        return [(title, [self[n] for n in names]) for title, names in self.GROUPS]


class RelationshipForm(forms.ModelForm):
    class Meta:
        model = Relationship
        fields = ["source", "rel_type", "target", "origin", "confidence", "note"]
        labels = {"source": "Source CI", "target": "Target CI", "rel_type": "Relationship"}
        widgets = {"note": forms.TextInput(attrs={"placeholder": "Optional note"}),
                   "confidence": forms.NumberInput(attrs={"min": 0, "max": 100})}

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        qs = services.ci_queryset(user).order_by("name")
        self.fields["source"].queryset = qs
        self.fields["target"].queryset = qs
        self.fields["confidence"].initial = 100

    def clean(self):
        # self-links (Relationship.clean) and duplicates (unique constraint) are validated by the model
        data = super().clean()
        s, t, rt = data.get("source"), data.get("target"), data.get("rel_type")
        if s and t and rt and s.pk != t.pk and not Relationship.objects.filter(source=s, target=t, rel_type=rt).exists():
            if services.would_cycle(s, t, rt):
                label = dict(Relationship._meta.get_field("rel_type").choices)[rt].lower()
                raise forms.ValidationError(f"“{s} {label} {t}” would create a dependency loop.")
        return data


class SoftwareForm(forms.ModelForm):
    class Meta:
        model = Software
        fields = ["name", "vendor", "version", "category", "description", "installs"]
        widgets = {"description": forms.Textarea(attrs={"rows": 3}), "installs": forms.CheckboxSelectMultiple(),
                   "name": forms.TextInput(attrs={"placeholder": "e.g. PostgreSQL"}),
                   "category": forms.TextInput(attrs={"placeholder": "e.g. Database", "list": "cmdb-sw-categories"})}
        labels = {"installs": "Installed on"}

    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["installs"].queryset = services.ci_queryset(user).exclude(ci_type=CIType.BUSINESS_DOMAIN).order_by("name")
        self.fields["installs"].required = False

    def clean(self):
        data = super().clean()
        name, version = (data.get("name") or "").strip(), (data.get("version") or "").strip()
        qs = Software.objects.filter(tenant_key=settings.LINKEDEYE_TENANT, name__iexact=name, version__iexact=version)
        if self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)
        if name and qs.exists():
            raise forms.ValidationError("This software and version is already registered.")
        return data

    def save(self, commit=True):
        obj = super().save(commit=False)
        obj.tenant_key = obj.tenant_key or settings.LINKEDEYE_TENANT
        if commit:
            obj.save()
            # keep installs the user cannot see (other sites) when a site-scoped user edits
            visible = set(self.fields["installs"].queryset.values_list("pk", flat=True))
            hidden = [c for c in obj.installs.all() if c.pk not in visible] if obj.pk else []
            obj.installs.set(list(self.cleaned_data.get("installs") or []) + hidden)
        return obj


class LicenseForm(forms.ModelForm):
    class Meta:
        model = License
        fields = ["product", "vendor", "software", "license_type", "seats", "expiry", "cost", "reference", "notes"]
        widgets = {"expiry": DateInput(), "notes": forms.Textarea(attrs={"rows": 3}),
                   "cost": forms.NumberInput(attrs={"step": "0.01", "min": "0"}),
                   "seats": forms.NumberInput(attrs={"min": 0}),
                   "product": forms.TextInput(attrs={"placeholder": "e.g. Red Hat Enterprise Linux"}),
                   "license_type": forms.TextInput(attrs={"placeholder": "Subscription, Perpetual…"})}
        labels = {"software": "Software (usage source)", "reference": "Contract / PO reference"}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["software"].queryset = Software.objects.filter(tenant_key=settings.LINKEDEYE_TENANT).order_by("name", "version")

    def save(self, commit=True):
        obj = super().save(commit=False)
        obj.tenant_key = obj.tenant_key or settings.LINKEDEYE_TENANT
        if commit:
            obj.save()
        return obj


class ImportForm(forms.Form):
    file = forms.FileField(label="CSV file", help_text="UTF-8 CSV, max 2 MB. Existing items with the same name are updated.")
    update_existing = forms.BooleanField(label="Update existing items with the same name", required=False, initial=True)

    def clean_file(self):
        f = self.cleaned_data["file"]
        if f.size > MAX_IMPORT_BYTES:
            raise forms.ValidationError("The file is larger than 2 MB.")
        if not f.name.lower().endswith((".csv", ".txt")):
            raise forms.ValidationError("Upload a .csv file.")
        return f


TYPE_LOOKUP = {**{v: v for v in CIType.values}, **{l.lower(): v for v, l in CIType.choices}}
STATUS_LOOKUP = {**{v: v for v in CIStatus.values}, **{l.lower(): v for v, l in CIStatus.choices}}
ENV_LOOKUP = {**{v: v for v in Environment.values}, **{l.lower(): v for v, l in Environment.choices}, "production": "prod",
              "development": "dev"}
