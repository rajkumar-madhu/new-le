import zoneinfo

from django import forms
from django.conf import settings
from django.contrib.auth import get_user_model, password_validation
from django.contrib.auth.forms import UsernameField
from django.utils.text import slugify

from core.models import Membership, Site

User = get_user_model()

ROLE_CHOICES = Membership.ROLES
ALL_SITES = ""


def site_choices(include_all=True):
    rows = [(ALL_SITES, "All sites")] if include_all else []
    rows += [(str(s.pk), s.name) for s in Site.objects.filter(tenant_key=settings.LINKEDEYE_TENANT).order_by("name")]
    return rows


def _site_from(value):
    if value in (None, "", ALL_SITES):
        return None
    return Site.objects.filter(tenant_key=settings.LINKEDEYE_TENANT, pk=value).first()


class _EmailMixin:
    def clean_email(self):
        email = (self.cleaned_data.get("email") or "").strip()
        if email:
            qs = User.objects.filter(email__iexact=email)
            if self.instance is not None and self.instance.pk:
                qs = qs.exclude(pk=self.instance.pk)
            if qs.exists():
                raise forms.ValidationError("Another user already has this e-mail address.")
        return email


class PasswordChoiceMixin:
    """Either generate a strong password (shown once) or set one that passes AUTH_PASSWORD_VALIDATORS."""

    def _init_password_fields(self):
        self.fields["password_mode"] = forms.ChoiceField(
            choices=[("generate", "Generate a strong password (shown once)"), ("set", "Set a password")],
            initial="generate", widget=forms.RadioSelect, label="Method")
        self.fields["password1"] = forms.CharField(label="New password", required=False, strip=False,
                                                   widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
                                                   help_text=password_validation.password_validators_help_text_html())
        self.fields["password2"] = forms.CharField(label="Confirm password", required=False, strip=False,
                                                   widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}))

    def _clean_password(self, cleaned, user):
        if cleaned.get("password_mode") != "set":
            return
        p1, p2 = cleaned.get("password1") or "", cleaned.get("password2") or ""
        if not p1:
            self.add_error("password1", "Enter a password, or choose to generate one.")
            return
        if p1 != p2:
            self.add_error("password2", "The two passwords do not match.")
            return
        try:
            password_validation.validate_password(p1, user)
        except forms.ValidationError as e:
            self.add_error("password1", e)


class UserCreateForm(_EmailMixin, PasswordChoiceMixin, forms.ModelForm):
    username = UsernameField(max_length=150, help_text="Letters, digits and @/./+/-/_ only.")
    site = forms.ChoiceField(label="Initial site", required=False)
    role = forms.ChoiceField(label="Initial role", choices=ROLE_CHOICES, initial="viewer")

    class Meta:
        model = User
        fields = ["username", "first_name", "last_name", "email"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.instance = User()
        self.fields["site"].choices = site_choices()
        self._init_password_fields()

    def clean_username(self):
        username = self.cleaned_data["username"]
        if User.objects.filter(username__iexact=username).exists():
            raise forms.ValidationError("A user with this username already exists.")
        return username

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("site") not in (None, ALL_SITES) and _site_from(cleaned.get("site")) is None:
            self.add_error("site", "Unknown site.")
        probe = User(username=cleaned.get("username") or "", first_name=cleaned.get("first_name") or "",
                     last_name=cleaned.get("last_name") or "", email=cleaned.get("email") or "")
        self._clean_password(cleaned, probe)
        return cleaned

    @property
    def site_obj(self):
        return _site_from(self.cleaned_data.get("site"))


class UserEditForm(_EmailMixin, forms.ModelForm):
    class Meta:
        model = User
        fields = ["first_name", "last_name", "email", "is_staff"]
        labels = {"is_staff": "Django admin access (staff)"}
        help_texts = {"is_staff": "Lets the user sign in to the Django admin. Without memberships, staff users are "
                                  "operators on all sites."}


class MembershipForm(forms.Form):
    site = forms.ChoiceField(label="Site", required=False)
    role = forms.ChoiceField(label="Role", choices=ROLE_CHOICES, initial="viewer")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["site"].choices = site_choices()

    def clean_site(self):
        value = self.cleaned_data.get("site")
        if value in (None, ALL_SITES):
            return None
        site = _site_from(value)
        if site is None:
            raise forms.ValidationError("Unknown site.")
        return site


class SetPasswordForm(PasswordChoiceMixin, forms.Form):
    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)
        self._init_password_fields()

    def clean(self):
        cleaned = super().clean()
        self._clean_password(cleaned, self.user)
        return cleaned


def timezone_choices(current=None):
    zones = sorted(zoneinfo.available_timezones())
    if current and current not in zones:
        zones.insert(0, current)
    return [(z, z.replace("_", " ")) for z in zones]


class SiteForm(forms.ModelForm):
    timezone = forms.ChoiceField(label="Timezone")

    class Meta:
        model = Site
        fields = ["name", "code", "region", "timezone", "criticality", "description"]
        help_texts = {"code": "Short identifier (letters, digits, hyphens). Leave blank to derive it from the name.",
                      "name": "Records in other modules refer to the site by this name."}
        widgets = {"description": forms.Textarea(attrs={"rows": 3})}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["code"].required = False
        current = self.instance.timezone if self.instance and self.instance.pk else None
        self.fields["timezone"].choices = timezone_choices(current)
        if not self.instance.pk:
            self.fields["timezone"].initial = getattr(settings, "TIME_ZONE", "Asia/Kolkata")

    def _scope(self):
        qs = Site.objects.filter(tenant_key=settings.LINKEDEYE_TENANT)
        return qs.exclude(pk=self.instance.pk) if self.instance.pk else qs

    def clean_name(self):
        name = " ".join((self.cleaned_data.get("name") or "").split())
        if not name:
            raise forms.ValidationError("Enter a name.")
        if self.instance.pk and " ".join(self.instance.name.split()) == name:
            # Unchanged: keep the exact stored spelling (other modules match site names exactly) and skip the
            # duplicate checks, because bootstrap_sites can create case variants such as "Mumbai" and "mumbai".
            return self.instance.name
        if name.lower() == "all sites":
            raise forms.ValidationError("“All Sites” is reserved for records that apply everywhere.")
        if self._scope().filter(name__iexact=name).exists():
            raise forms.ValidationError("A site with this name already exists.")
        return name

    def clean(self):
        cleaned = super().clean()
        code = (cleaned.get("code") or "").strip().lower()
        if not code and cleaned.get("name"):
            base = slugify(cleaned["name"])[:50] or "site"
            code, i = base, 2
            while self._scope().filter(code__iexact=code).exists():
                code, i = f"{base}-{i}", i + 1
        if code and self.instance.pk and code == (self.instance.code or "").lower():
            cleaned["code"] = self.instance.code          # unchanged
        elif code:
            if self._scope().filter(code__iexact=code).exists():
                self.add_error("code", "A site with this code already exists.")
            cleaned["code"] = code
        return cleaned
