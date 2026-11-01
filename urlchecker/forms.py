from django import forms

from .models import UrlCheck

# Common HTTP codes offered in the "Expected Status" select. An existing check whose code is not
# in this list keeps it (it is added to the choices when the form is bound to that check).
STATUS_CHOICES = [
    (200, "200 OK"), (201, "201 Created"), (202, "202 Accepted"), (204, "204 No Content"),
    (301, "301 Moved Permanently"), (302, "302 Found"), (304, "304 Not Modified"),
    (401, "401 Unauthorized"), (403, "403 Forbidden"), (404, "404 Not Found"),
]

# Fields shown in the compact grid; the rest live under "Advanced options".
MAIN_FIELDS = ["name", "url", "check_type", "method", "expected_status", "interval_seconds", "site", "tags"]
ADVANCED_FIELDS = ["expected_text", "degraded_ms", "timeout_seconds"]


class UrlCheckForm(forms.ModelForm):
    class Meta:
        model = UrlCheck
        fields = ["name", "url", "check_type", "method", "expected_status", "interval_seconds", "site", "tags",
                  "expected_text", "degraded_ms", "timeout_seconds", "follow_redirects", "enabled"]
        widgets = {
            "name": forms.TextInput(attrs={"placeholder": "e.g. NSE Web Portal"}),
            "url": forms.URLInput(attrs={"placeholder": "https://example.com"}),
            "site": forms.TextInput(attrs={"placeholder": "Mumbai (NSE)"}),
            "tags": forms.TextInput(attrs={"placeholder": "e.g. trading, production"}),
            "expected_text": forms.TextInput(attrs={"placeholder": "Optional"}),
        }
        labels = {"url": "URL", "check_type": "Check Type", "expected_status": "Expected Status",
                  "interval_seconds": "Check Interval", "site": "Site / Location", "tags": "Tags (comma separated)",
                  "expected_text": "Expected Text", "degraded_ms": "Degraded Above (ms)", "timeout_seconds": "Timeout (s)",
                  "follow_redirects": "Follow Redirects"}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        choices = list(STATUS_CHOICES)
        current = self.instance.expected_status if self.instance and self.instance.pk else None
        if current and current not in dict(choices):
            choices.append((current, str(current)))
            choices.sort()
        field = self.fields["expected_status"]
        field.widget = forms.Select(choices=choices)
        field.widget.is_required = True
        # Same stored values as the model; only the label reads like the protocol.
        self.fields["check_type"].choices = [("web", "HTTP/HTTPS"), ("api", "API")]

    def main_fields(self):
        return [self[n] for n in MAIN_FIELDS]

    def advanced_fields(self):
        return [self[n] for n in ADVANCED_FIELDS]

    def advanced_has_errors(self):
        return any(self[n].errors for n in ADVANCED_FIELDS + ["enabled"])

    def clean_url(self):
        url = self.cleaned_data["url"]
        if not url.lower().startswith(("http://", "https://")):
            raise forms.ValidationError("Only http:// and https:// URLs can be checked.")
        return url
