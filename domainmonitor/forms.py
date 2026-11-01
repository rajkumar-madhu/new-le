from django import forms

from .models import DOMAIN_TYPES, Domain


class DomainForm(forms.ModelForm):
    domain_type = forms.ChoiceField(choices=[(t, t) for t in DOMAIN_TYPES], label="Type")

    class Meta:
        model = Domain
        fields = ["hostname", "domain_type", "site_key", "group", "description", "check_interval_seconds", "monitor_enabled"]
        labels = {"hostname": "Domain name", "site_key": "Site", "check_interval_seconds": "Check interval (s)",
                  "monitor_enabled": "Monitor availability, DNS and SSL"}
        widgets = {"hostname": forms.TextInput(attrs={"placeholder": "nse.finspot.in"}),
                   "site_key": forms.TextInput(attrs={"placeholder": "Mumbai (NSE)"}),
                   "group": forms.TextInput(attrs={"placeholder": "e.g. Trading"}),
                   "description": forms.Textarea(attrs={"rows": 2})}

    def clean_hostname(self):
        return self.cleaned_data["hostname"].strip().lower().rstrip(".")

    def clean_check_interval_seconds(self):
        v = self.cleaned_data["check_interval_seconds"]
        if v < 60:
            raise forms.ValidationError("Minimum interval is 60 seconds.")
        return v
