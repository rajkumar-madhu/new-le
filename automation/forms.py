import json

from django import forms

from . import services
from .models import SEVERITY_RANK, Rule, Runbook, Template
from .templating import PRIORITIES, TemplateValuesMixin, build_field, specs_for


def _site_choices(sites, blank=None):
    out = [(blank[0], blank[1])] if blank else []
    out.append(("All Sites", "All Sites"))
    out += [(s, s) for s in sites if s and s != "All Sites"]
    return out


def _unique(form, field, value):
    """Model forms exclude tenant_key, so Django skips the (tenant_key, name) constraint: check it here."""
    model = form._meta.model
    qs = model.objects.filter(tenant_key=services.tenant(), **{f"{field}__iexact": value})
    if form.instance.pk:
        qs = qs.exclude(pk=form.instance.pk)
    if qs.exists():
        raise forms.ValidationError(f"A {model._meta.verbose_name} with this {field} already exists.")
    return value


def _json_object(text, label="Value"):
    text = (text or "").strip()
    if not text:
        return {}
    try:
        value = json.loads(text)
    except ValueError as e:
        raise forms.ValidationError(f"{label} is not valid JSON: {e}") from None
    if not isinstance(value, dict):
        raise forms.ValidationError(f"{label} must be a JSON object, e.g. {{\"key\": \"value\"}}.")
    return value


# ------------------------------------------------------------------ runbooks
class RunbookForm(forms.ModelForm):
    class Meta:
        model = Runbook
        fields = ["title", "service", "ci_name", "site", "owner", "tags", "last_reviewed", "symptoms", "steps"]
        widgets = {
            "symptoms": forms.Textarea(attrs={"rows": 4, "placeholder": "e.g. URL check “Trading portal” is Down; users see HTTP 502."}),
            "steps": forms.Textarea(attrs={"rows": 12, "class": "mono",
                                           "placeholder": "1. Confirm the alert on the URL Checker page.\n2. Check the "
                                                          "load balancer pool.\n   Commands can continue on the next line.\n"
                                                          "3. Escalate to the application team if not resolved."}),
            "last_reviewed": forms.DateInput(attrs={"type": "date"}, format="%Y-%m-%d"),
        }

    def __init__(self, *args, sites=(), **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["site"] = forms.ChoiceField(choices=_site_choices(sites), initial="All Sites", label="Site")
        cur = self.instance.site if self.instance and self.instance.pk else None
        if cur and cur not in dict(self.fields["site"].choices):
            self.fields["site"].choices = list(self.fields["site"].choices) + [(cur, cur)]
        self.fields["tags"].widget.attrs["placeholder"] = "e.g. network, nse, p1"
        self.fields["steps"].error_messages["required"] = "Add at least one step."
        self.fields["steps"].help_text = ("One step per line. Lines starting with 1. / 2) / - start a new step; other lines "
                                          "continue the step above. Lines starting with “$ ” are shown as commands.")

    def clean_title(self):
        return _unique(self, "title", self.cleaned_data["title"].strip())

    def clean_tags(self):
        tags = [t.strip() for t in self.cleaned_data.get("tags", "").split(",") if t.strip()]
        return ", ".join(dict.fromkeys(tags))[:200]

    def clean_steps(self):
        steps = (self.cleaned_data.get("steps") or "").strip()
        if not steps:
            raise forms.ValidationError("Add at least one step.")
        return steps


# ------------------------------------------------------------------ rules
class RuleForm(forms.ModelForm):
    priority = forms.ChoiceField(choices=PRIORITIES, initial="P3", required=False, label="Incident priority")
    incident_title = forms.CharField(max_length=200, required=False, label="Incident title",
                                     help_text="Blank = use the event title.")
    trigger = forms.CharField(max_length=200, required=False, label="StackStorm trigger",
                              help_text="Webhook name appended to LINKEDEYE_STACKSTORM_URL, e.g. linkedeye_restart.")
    webhook_url = forms.CharField(max_length=500, required=False, label="Webhook URL",
                                  help_text="Must pass the probe SSRF policy (no link-local; private ranges only if allowed).")
    payload = forms.CharField(required=False, label="Extra payload (JSON)", widget=forms.Textarea(attrs={"rows": 3, "class": "mono"}),
                              help_text="Optional JSON object merged into the body sent to StackStorm / the webhook.")

    class Meta:
        model = Rule
        fields = ["name", "description", "enabled", "match_source", "min_severity", "title_contains", "site",
                  "cooldown_minutes", "action", "runbook"]

    def __init__(self, *args, sites=(), runbooks=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["site"] = forms.ChoiceField(choices=[("", "Any site")] + [(s, s) for s in sites if s and s != "All Sites"],
                                                required=False, label="Site",
                                                help_text=Rule._meta.get_field("site").help_text)
        cur = self.instance.site if self.instance and self.instance.pk else None
        if cur and cur not in dict(self.fields["site"].choices):
            self.fields["site"].choices = list(self.fields["site"].choices) + [(cur, cur)]
        if runbooks is not None:
            self.fields["runbook"].queryset = runbooks
        self.fields["runbook"].required = False
        self.fields["runbook"].help_text = "Required for “Link runbook”; for “Open incident” it is named in the description."
        self.fields["match_source"].widget.attrs["placeholder"] = "any source"
        self.fields["title_contains"].widget.attrs["placeholder"] = "any title"
        if not self.instance.pk:
            self.fields["enabled"].initial = True
        p = self.instance.params if self.instance and self.instance.pk else {}
        if p:
            self.fields["priority"].initial = p.get("priority") or "P3"
            self.fields["incident_title"].initial = p.get("title", "")
            self.fields["trigger"].initial = p.get("trigger", "")
            self.fields["webhook_url"].initial = p.get("url", "")
            if isinstance(p.get("payload"), dict) and p["payload"]:
                self.fields["payload"].initial = json.dumps(p["payload"], indent=2)

    def clean_name(self):
        return _unique(self, "name", self.cleaned_data["name"].strip())

    def clean_match_source(self):
        items = [s.strip().lower() for s in self.cleaned_data.get("match_source", "").split(",") if s.strip()]
        return ", ".join(dict.fromkeys(items))[:200]

    def clean_payload(self):
        return _json_object(self.cleaned_data.get("payload"), "Extra payload")

    def clean(self):
        data = super().clean()
        action = data.get("action")
        params = {}
        if action == "open_incident":
            params["priority"] = data.get("priority") or "P3"
            if data.get("incident_title"):
                params["title"] = data["incident_title"].strip()
        elif action == "stackstorm":
            trig = (data.get("trigger") or "").strip()
            if not trig:
                self.add_error("trigger", "Enter the StackStorm trigger (webhook name).")
            elif not services.valid_trigger(trig):
                self.add_error("trigger", "Use letters, digits, '.', '_', '-' and '/' only.")
            params["trigger"] = trig
        elif action == "webhook":
            url = (data.get("webhook_url") or "").strip()
            if not url:
                self.add_error("webhook_url", "Enter the webhook URL.")
            else:
                try:
                    services.check_webhook_url(url)
                except services.WebhookError as e:
                    self.add_error("webhook_url", str(e))
            params["url"] = url
        elif action == "link_runbook":
            if not data.get("runbook"):
                self.add_error("runbook", "Choose the runbook to link.")
        if action in ("stackstorm", "webhook") and data.get("payload"):
            params["payload"] = data["payload"]
        self.instance.action_params = params
        return data


class RuleTestForm(forms.Form):
    """A sample event to evaluate a rule against."""
    source = forms.CharField(max_length=40, initial="urlchecker")
    severity = forms.ChoiceField(choices=[(k, k.title()) for k in sorted(SEVERITY_RANK, key=SEVERITY_RANK.get, reverse=True)],
                                 initial="critical")
    title = forms.CharField(max_length=200, initial="Example check is Down")
    message = forms.CharField(required=False, widget=forms.Textarea(attrs={"rows": 2}))
    site = forms.CharField(max_length=100, required=False)
    fingerprint = forms.CharField(max_length=200, required=False, help_text="Used for the cooldown check.")
    run = forms.BooleanField(required=False, label="Run the action for real",
                             help_text="Records an execution and may call StackStorm, a webhook or open an incident.")


# ------------------------------------------------------------------ StackStorm
class TriggerForm(forms.Form):
    trigger = forms.CharField(max_length=200, help_text="Webhook name appended to the StackStorm URL, e.g. linkedeye_restart.")
    payload = forms.CharField(required=False, widget=forms.Textarea(attrs={"rows": 6, "class": "mono"}),
                              help_text="JSON object sent as the request body.")

    def clean_trigger(self):
        t = self.cleaned_data["trigger"].strip()
        if not services.valid_trigger(t):
            raise forms.ValidationError("Use letters, digits, '.', '_', '-' and '/' only.")
        return t

    def clean_payload(self):
        return _json_object(self.cleaned_data.get("payload"), "Payload")


# ------------------------------------------------------------------ templates
class TemplateForm(TemplateValuesMixin, forms.ModelForm):
    """Template editor: name/description plus every field of the kind, all optional (defaults)."""
    prefix_key = "v_"

    class Meta:
        model = Template
        fields = ["name", "description"]

    def __init__(self, *args, kind, sites=(), **kwargs):
        super().__init__(*args, **kwargs)
        self.kind = kind
        defaults = self.instance.values if self.instance and self.instance.pk else {}
        for s in specs_for(kind):
            initial = defaults.get(s.key)
            f = build_field(s, False, sites, initial=initial)
            if initial is not None:
                f.initial = str(initial) if s.type == "intchoice" else initial
            elif s.default not in (None, ""):
                f.initial = str(s.default) if s.type == "intchoice" else s.default
            self.fields[self.prefix_key + s.key] = f

    def clean_name(self):
        return _unique(self, "name", self.cleaned_data["name"].strip())

    def save(self, commit=True):
        obj = super().save(commit=False)
        obj.kind = self.kind
        obj.fields = self.values()
        if commit:
            obj.save()
        return obj
