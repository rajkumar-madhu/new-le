from urllib.parse import urlsplit

from django import forms
from django.conf import settings
from django.core.exceptions import ValidationError

from . import services
from .models import EXPORTER_TYPES, Category, Exporter


class ExporterForm(forms.ModelForm):
    site = forms.ChoiceField(required=False)

    GROUPS = [
        ("Exporter", ["name", "exporter_type", "category", "target"]),
        ("Scraping", ["metrics_url", "site", "enabled"]),
        ("Notes", ["description"]),
    ]

    class Meta:
        model = Exporter
        fields = ["name", "exporter_type", "category", "target", "metrics_url", "site", "enabled", "description"]
        widgets = {
            "name": forms.TextInput(attrs={"placeholder": "e.g. node-exporter-01", "autocomplete": "off"}),
            "exporter_type": forms.TextInput(attrs={"placeholder": "e.g. Node Exporter", "list": "ob-types"}),
            "target": forms.TextInput(attrs={"placeholder": "e.g. srv-app-01 or 10.10.1.20"}),
            "metrics_url": forms.URLInput(attrs={"placeholder": "http://10.10.1.20:9100/metrics"}),
            "description": forms.Textarea(attrs={"rows": 3}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        current = self.instance.site if self.instance and self.instance.pk else ""
        names = set(services.site_names(Exporter.objects.filter(tenant_key=settings.LINKEDEYE_TENANT)))
        if current:
            names.add(current)
        names.discard("All Sites")
        self.fields["site"].choices = ([("", "(No site)"), ("All Sites", "All Sites")]
                                       + [(n, n) for n in sorted(names, key=str.lower)])
        self.fields["category"].choices = Category.choices
        self.fields["exporter_type"].help_text = "Free text; common types are suggested."

    @property
    def groups(self):
        return [(title, [self[f] for f in names]) for title, names in self.GROUPS]

    @property
    def type_suggestions(self):
        return EXPORTER_TYPES

    def clean_name(self):
        name = self.cleaned_data["name"].strip()
        qs = Exporter.objects.filter(tenant_key=settings.LINKEDEYE_TENANT, name__iexact=name)
        if self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise ValidationError("An exporter with this name already exists.")
        return name

    def clean_metrics_url(self):
        url = (self.cleaned_data.get("metrics_url") or "").strip()
        if url:
            parts = urlsplit(url)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                raise ValidationError("Use an http:// or https:// URL.")
            if parts.username or parts.password:
                raise ValidationError("Credentials in the URL are not supported.")
        return url


class ImportForm(forms.Form):
    file = forms.FileField(label="CSV file", help_text="Columns: name, type, category, target, metrics_url, site, enabled, "
                                                        "description. Max 1 MB, 1000 rows.")
    update_existing = forms.BooleanField(required=False, initial=False, label="Update exporters that already exist (matched by name)")
