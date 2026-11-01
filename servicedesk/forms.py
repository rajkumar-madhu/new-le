"""Ticket, comment and catalog forms. Status is never edited here: it moves only through workflow
transitions (services.transition) so every change is validated and lands on the timeline."""
from django import forms
from django.conf import settings
from django.contrib.auth import get_user_model

from core.access import can

from . import workflow as wf
from .models import CatalogItem, SlaPolicy, Ticket

DEFAULT_CATEGORIES = ["Access Management", "Application", "Database", "DNS", "Email", "Hardware", "Network",
                      "Security", "Server", "Software", "Storage"]
DT_FORMAT = "%Y-%m-%dT%H:%M"

COMMON = ["title", "description", "priority", "category", "client", "site", "assignee", "ci_name"]
KIND_FIELDS = {
    "incident": ["problem"],
    "problem": ["root_cause", "workaround"],
    "change": ["risk", "planned_start", "planned_end", "implementation_plan", "backout_plan"],
    "request": ["catalog_item"],
}
WIDE = {"title", "description", "root_cause", "workaround", "implementation_plan", "backout_plan", "resolution"}


# Largest primary keys the database can hold (BigAutoField for our models, AutoField for auth users). Larger
# numbers in a request would overflow the database driver (500 on SQLite, DataError on PostgreSQL).
MAX_PK = 2 ** 63 - 1
MAX_USER_PK = 2 ** 31 - 1


def parse_pk(value, limit=MAX_PK):
    """int for a plain positive id within range, else None (bad ids are treated as 'not found')."""
    value = str(value or "").strip()
    if not (value.isascii() and value.isdigit()):
        return None
    n = int(value)
    return n if 0 < n <= limit else None


class BoundedModelChoiceField(forms.ModelChoiceField):
    """ModelChoiceField that rejects out-of-range ids as an invalid choice instead of crashing the query."""
    limit = MAX_PK

    def to_python(self, value):
        if value not in self.empty_values and parse_pk(value, self.limit) is None:
            raise forms.ValidationError(self.error_messages["invalid_choice"], code="invalid_choice")
        return super().to_python(value)


def assignable_users(site=None):
    """Active users who may work tickets (operate) on the site, by display name.

    Memberships are prefetched and handed to core.access's per-user cache, so checking 300 users costs two
    queries instead of one per user."""
    from django.db.models import Prefetch

    from core.models import Membership
    qs = (get_user_model().objects.filter(is_active=True).order_by("first_name", "username")
          .prefetch_related(Prefetch("le_memberships", queryset=Membership.objects.select_related("site")))[:300])
    users = []
    for u in qs:
        u._le_memberships = list(u.le_memberships.all())
        if can(u, "operate", site or None):
            users.append(u)
    return users


def user_label(u):
    return u.get_full_name() or u.get_username()


class UserChoiceField(BoundedModelChoiceField):
    limit = MAX_USER_PK

    def label_from_instance(self, obj):
        return user_label(obj)


class TicketForm(forms.ModelForm):
    """Create/edit form; the fields shown depend on the ticket kind."""

    class Meta:
        model = Ticket
        fields = COMMON + sorted({f for fs in KIND_FIELDS.values() for f in fs}) + ["resolution"]
        widgets = {
            "description": forms.Textarea(attrs={"rows": 5}),
            "root_cause": forms.Textarea(attrs={"rows": 3}),
            "workaround": forms.Textarea(attrs={"rows": 3}),
            "implementation_plan": forms.Textarea(attrs={"rows": 4}),
            "backout_plan": forms.Textarea(attrs={"rows": 3}),
            "resolution": forms.Textarea(attrs={"rows": 3}),
            "planned_start": forms.DateTimeInput(attrs={"type": "datetime-local"}, format=DT_FORMAT),
            "planned_end": forms.DateTimeInput(attrs={"type": "datetime-local"}, format=DT_FORMAT),
            "category": forms.TextInput(attrs={"list": "sd-categories", "autocomplete": "off"}),
            "client": forms.TextInput(attrs={"list": "sd-clients", "autocomplete": "off"}),
            "site": forms.TextInput(attrs={"list": "sd-sites", "autocomplete": "off"}),
            "ci_name": forms.TextInput(attrs={"list": "sd-cis", "autocomplete": "off"}),
        }
        field_classes = {"problem": BoundedModelChoiceField, "catalog_item": BoundedModelChoiceField}
        labels = {"ci_name": "Configuration item", "catalog_item": "Catalog item", "problem": "Linked problem",
                  "planned_start": "Planned start", "planned_end": "Planned end", "resolution": "Resolution notes"}

    def __init__(self, *args, kind="incident", user=None, problems=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.kind = self.instance.kind if self.instance.pk else kind
        self.user = user
        keep = set(COMMON) | set(KIND_FIELDS[self.kind])
        if self.instance.pk:
            keep.add("resolution")
        for name in list(self.fields):
            if name not in keep:
                del self.fields[name]
        for name in ("planned_start", "planned_end"):
            if name in self.fields:
                self.fields[name].input_formats = [DT_FORMAT, "%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S"]
        tenant = settings.LINKEDEYE_TENANT
        self.fields["assignee"] = UserChoiceField(queryset=get_user_model().objects.filter(
            pk__in=[u.pk for u in assignable_users()]), required=False, label="Assignee", empty_label="Unassigned")
        if "problem" in self.fields:
            # `problems`: the tickets the user may see (site-scoped); never offer problems from other sites
            base = problems if problems is not None else Ticket.objects.filter(tenant_key=tenant)
            qs = base.filter(kind="problem").exclude(status="closed")
            if self.instance.problem_id:
                qs = qs | Ticket.objects.filter(pk=self.instance.problem_id)
            self.fields["problem"].queryset = qs.order_by("-opened_at")
            self.fields["problem"].label_from_instance = lambda t: f"{t.number} · {t.title}"[:90]
            self.fields["problem"].empty_label = "Not linked"
        if "catalog_item" in self.fields:
            self.fields["catalog_item"].queryset = CatalogItem.objects.filter(tenant_key=tenant, active=True)
            self.fields["catalog_item"].empty_label = "None"
        if "risk" in self.fields:
            self.fields["risk"].choices = [("", "Not assessed")] + list(wf.RISKS)
        self.fields["priority"].choices = [(k, f"{k} · {v}") for k, v in wf.PRIORITIES]
        self.fields["site"].help_text = "Leave blank or “All Sites” for a global ticket."
        self.fields["title"].widget.attrs.setdefault("placeholder", "Short summary, e.g. “VPN connection drops for branch users”")

    def clean_site(self):
        site = (self.cleaned_data.get("site") or "").strip()
        if self.user is not None and not can(self.user, "operate", site if site not in ("", "All Sites") else None):
            raise forms.ValidationError("You cannot raise or move tickets for this site.")
        return site

    def clean(self):
        data = super().clean()
        assignee = data.get("assignee")
        if assignee is not None and "site" in data and (self.instance.pk is None or "assignee" in self.changed_data
                                                         or "site" in self.changed_data):
            site = data["site"]
            if not can(assignee, "operate", site if site not in ("", "All Sites") else None):
                self.add_error("assignee", f"{user_label(assignee)} cannot work tickets on this site.")
        start, end = data.get("planned_start"), data.get("planned_end")
        if start and end and end <= start:
            self.add_error("planned_end", "The planned end must be after the planned start.")
        return data

    @property
    def main_fields(self):
        return [self[n] for n in self.fields]


class CommentForm(forms.Form):
    body = forms.CharField(widget=forms.Textarea(attrs={"rows": 3, "placeholder": "Add a comment or work note…"}),
                           max_length=10000, label="Comment")


class CatalogItemForm(forms.ModelForm):
    class Meta:
        model = CatalogItem
        fields = ["name", "category", "description", "fulfilment_hours", "default_priority", "active"]
        widgets = {"description": forms.Textarea(attrs={"rows": 3}),
                   "category": forms.TextInput(attrs={"list": "sd-catalog-categories", "autocomplete": "off"})}
        labels = {"fulfilment_hours": "Fulfilment target (hours)"}

    def clean_name(self):
        name = self.cleaned_data["name"].strip()
        qs = CatalogItem.objects.filter(tenant_key=settings.LINKEDEYE_TENANT, name__iexact=name)
        if self.instance.pk:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise forms.ValidationError("A catalog item with this name already exists.")
        return name

    def clean_fulfilment_hours(self):
        v = self.cleaned_data["fulfilment_hours"]
        if not 1 <= v <= 24 * 90:
            raise forms.ValidationError("Use between 1 and 2160 hours.")
        return v


class RequestForm(forms.Form):
    details = forms.CharField(widget=forms.Textarea(attrs={"rows": 4, "placeholder": "What do you need? Include names, systems, dates…"}),
                              required=False, max_length=5000, label="Details")
    site = forms.CharField(required=False, max_length=100, widget=forms.TextInput(attrs={"list": "sd-sites", "autocomplete": "off"}))
    client = forms.CharField(required=False, max_length=100, widget=forms.TextInput(attrs={"list": "sd-clients", "autocomplete": "off"}))


class SlaPolicyForm(forms.ModelForm):
    class Meta:
        model = SlaPolicy
        fields = ["name", "response_minutes", "resolution_minutes", "active"]

    def clean(self):
        data = super().clean()
        resp, res = data.get("response_minutes"), data.get("resolution_minutes")
        if resp is not None and res is not None and res < resp:
            self.add_error("resolution_minutes", "Resolution target must not be shorter than the response target.")
        for k in ("response_minutes", "resolution_minutes"):
            if data.get(k) is not None and data[k] < 1:
                self.add_error(k, "Must be at least 1 minute.")
        return data
