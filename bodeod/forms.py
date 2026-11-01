from django import forms

from .models import GLOBAL_SITES, ChecklistItem, Holiday, Mode
from .services import MAX_CSV_BYTES, modes_qs, user_can


def site_names():
    from django.conf import settings

    from core.models import Site
    return list(Site.objects.filter(tenant_key=settings.LINKEDEYE_TENANT).order_by("name").values_list("name", flat=True))


class ModeForm(forms.ModelForm):
    class Meta:
        model = Mode
        fields = ["code", "name", "description", "site", "window_start", "window_end", "auto_run_time",
                  "refresh_checks", "enabled"]
        widgets = {
            "window_start": forms.TimeInput(attrs={"type": "time"}, format="%H:%M"),
            "window_end": forms.TimeInput(attrs={"type": "time"}, format="%H:%M"),
            "auto_run_time": forms.TimeInput(attrs={"type": "time"}, format="%H:%M"),
            "description": forms.TextInput(),
        }
        labels = {"window_start": "Window start (IST)", "window_end": "Window end (IST)",
                  "auto_run_time": "Auto-run at (IST)", "refresh_checks": "Re-run referenced checks before validating"}

    def __init__(self, *args, tenant_key=None, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.tenant_key = tenant_key
        self.user = user
        if self.instance.pk:
            self.fields["code"].disabled = True
        # the site must be a configured site (or "All Sites"), not free text
        names = site_names()
        current = self.instance.site if self.instance.pk else ""
        if current and current not in names and current not in GLOBAL_SITES:
            names.append(current)  # keep a legacy value selectable
        self.fields["site"] = forms.ChoiceField(
            choices=[("All Sites", "All Sites")] + [(n, n) for n in names], initial="All Sites",
            label="Site", help_text=Mode._meta.get_field("site").help_text)

    def clean_site(self):
        site = self.cleaned_data.get("site") or "All Sites"
        if self.user is not None and not user_can(self.user, "admin", site):
            raise forms.ValidationError(f"You are not an administrator of {site}.")
        return site

    def clean(self):
        data = super().clean()
        start, end, auto = data.get("window_start"), data.get("window_end"), data.get("auto_run_time")
        if start and end and end <= start:
            self.add_error("window_end", "The window must end after it starts (same day, IST).")
        if auto and start and end and not (start <= auto < end):
            self.add_error("auto_run_time", "The auto-run time must fall inside the window.")
        code = data.get("code")
        if code and not self.instance.pk and modes_qs().filter(code=code).exists():
            self.add_error("code", f"Mode {code} already exists.")
        return data


class ChecklistItemForm(forms.ModelForm):
    class Meta:
        model = ChecklistItem
        fields = ["mode", "order", "name", "kind", "ref_name", "critical", "enabled", "instructions"]
        widgets = {"instructions": forms.Textarea(attrs={"rows": 3}),
                   "ref_name": forms.TextInput(attrs={"list": "bod-refs", "autocomplete": "off"})}
        labels = {"ref_name": "Reference", "critical": "Critical (fails the run)"}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["mode"].queryset = modes_qs()
        self.fields["mode"].empty_label = None
        self.fields["order"].widget.attrs["min"] = 0

    def clean(self):
        data = super().clean()
        kind, ref = data.get("kind"), (data.get("ref_name") or "").strip()
        if kind and kind != "manual" and not ref:
            self.add_error("ref_name", "Name the URL check, TCP check or domain hostname to validate.")
        if kind == "manual":
            ref = ""
        data["ref_name"] = ref
        mode, name = data.get("mode"), data.get("name")
        if mode and name:
            clash = ChecklistItem.objects.filter(mode=mode, name=name).exclude(pk=self.instance.pk)
            if clash.exists():
                self.add_error("name", f"{mode.code} already has an item with this name.")
        return data


class HolidayForm(forms.ModelForm):
    class Meta:
        model = Holiday
        fields = ["date", "exchange", "description"]
        widgets = {"date": forms.DateInput(attrs={"type": "date"}, format="%Y-%m-%d")}

    def clean(self):
        data = super().clean()
        if data.get("date") and data.get("exchange"):
            from .services import tenant
            if Holiday.objects.filter(tenant_key=tenant(), date=data["date"], exchange=data["exchange"]).exclude(pk=self.instance.pk).exists():
                self.add_error("date", "A holiday for this exchange and date already exists.")
        return data


class HolidayUploadForm(forms.Form):
    file = forms.FileField(label="CSV file", help_text="Columns: date, description, exchange (optional).")
    default_exchange = forms.ChoiceField(choices=Holiday.EXCHANGES, initial="NSE", label="Exchange when the column is missing")

    def clean_file(self):
        f = self.cleaned_data["file"]
        if f.size > MAX_CSV_BYTES:
            raise forms.ValidationError(f"The file must be smaller than {MAX_CSV_BYTES // 1024} KB.")
        name = (f.name or "").lower()
        if not (name.endswith(".csv") or name.endswith(".txt")):
            raise forms.ValidationError("Upload a .csv file.")
        return f


class SignOffForm(forms.Form):
    note = forms.CharField(max_length=500, widget=forms.TextInput(attrs={"placeholder": "What did you verify?"}))
