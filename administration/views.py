"""Administration console: users & roles, sites, audit log, integrations, system health.

Every page requires the admin role on *All sites* (or superuser); see services.is_global_admin. The own-profile
page is open to every signed-in user. Every mutation is a CSRF-protected POST, checks permissions, writes an
audit row, adds a message and redirects."""
import csv
from datetime import datetime, time, timedelta
from functools import wraps

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model, update_session_auth_hash
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Count, Prefetch, Q
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_POST

from core.access import can, require
from core.audit import audit
from core.models import AuditEvent, Membership, Site

from . import services
from .forms import MembershipForm, SetPasswordForm, SiteForm, UserCreateForm, UserEditForm
from .models import IntegrationTest

User = get_user_model()
EXPORT_LIMIT = 50000
ONE_TIME_KEY = "administration_one_time_password"


# ------------------------------------------------------------------ helpers
def admin_required(view):
    """core.access 'admin' permission, and it must be held on All sites (or superuser)."""
    @require("admin")
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        if services.is_global_admin(request.user):
            return view(request, *args, **kwargs)
        if "/api/" in request.path or request.headers.get("Accept", "").startswith("application/json") or \
                request.method == "POST" and request.headers.get("X-CSRFToken"):
            return JsonResponse({"error": "admin role on All sites required"}, status=403)
        if request.method == "GET":
            raise PermissionDenied("The administration console needs the admin role on All sites.")
        messages.error(request, "The administration console needs the admin role on All sites.")
        return redirect("dashboard")
    wrapped.le_perm = "admin"
    return wrapped


def _per_page(request, default=20):
    try:
        return max(5, min(100, int(request.GET.get("per", default))))
    except (TypeError, ValueError):
        return default


def _query(request, *drop):
    q = request.GET.copy()
    for k in ("page",) + drop:
        q.pop(k, None)
    return q


def _csv(name, header, rows):
    resp = HttpResponse(content_type="text/csv; charset=utf-8")
    resp["Content-Disposition"] = f'attachment; filename="{name}"'
    w = csv.writer(resp)
    w.writerow(header)
    for r in rows:
        w.writerow(["" if v is None else _cell(v) for v in r])
    return resp


def _cell(v):
    """Neutralise spreadsheet formulas in exported text."""
    s = str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def _flash_password(request, user, password):
    request.session[ONE_TIME_KEY] = {"user": user.pk, "password": password}


def _pop_password(request, user):
    data = request.session.get(ONE_TIME_KEY)
    if data and data.get("user") == user.pk:
        request.session.pop(ONE_TIME_KEY, None)
        return data.get("password")
    return None


def _guard_superuser(request, target):
    """Only superusers may change another superuser's password or active state."""
    return target.is_superuser and not request.user.is_superuser and target.pk != request.user.pk


def _memberships_qs():
    return Membership.objects.select_related("site").order_by("site__name")


def _user_qs():
    return User.objects.prefetch_related(Prefetch("le_memberships", queryset=_memberships_qs()))


# ------------------------------------------------------------------ index & profile
@admin_required
def index(request):
    t = settings.LINKEDEYE_TENANT
    since = timezone.now() - timedelta(hours=24)
    users = User.objects.all()
    items = services.integrations()
    ctx = {
        "n_users": users.count(), "n_active": users.filter(is_active=True).count(),
        "n_admins": users.filter(Q(is_superuser=True) | Q(le_memberships__role="admin")).filter(is_active=True).distinct().count(),
        "n_sites": Site.objects.filter(tenant_key=t).count(),
        "n_unmapped": len(services.unmapped_site_names()),
        "n_audit": AuditEvent.objects.filter(occurred_at__gte=since).count(),
        "n_integrations": len(items), "n_configured": sum(1 for i in items if i["configured"]),
        "health": services.health_summary(),
        "recent": AuditEvent.objects.all()[:8],
    }
    return render(request, "administration/index.html", ctx)


@require_GET
def profile(request):
    user = request.user
    ms = list(_memberships_qs().filter(user=user))
    role, note = services.effective_role(user)
    sites = Site.objects.filter(tenant_key=settings.LINKEDEYE_TENANT).order_by("name")
    from core.access import role_for
    per_site = [{"site": s, "role": role_for(user, s.name)} for s in sites]
    ctx = {"profile": user, "memberships": ms, "role": role, "role_note": note, "per_site": per_site,
           "recent": AuditEvent.objects.filter(actor=user)[:15], "is_admin": services.is_global_admin(user),
           "can_operate": can(user, "operate")}
    return render(request, "administration/profile.html", ctx)


# ------------------------------------------------------------------ users
def _filtered_users(request):
    qs = _user_qs().order_by("username")
    g = request.GET
    q = g.get("q", "").strip()
    if q:
        qs = qs.filter(Q(username__icontains=q) | Q(first_name__icontains=q) | Q(last_name__icontains=q) | Q(email__icontains=q))
    status = g.get("status")
    if status == "active":
        qs = qs.filter(is_active=True)
    elif status == "inactive":
        qs = qs.filter(is_active=False)
    # Role and site conditions on memberships go into ONE filter() call so they apply to the same membership row
    # ("admin on site X"), not to two different memberships of the user (separate joins).
    member = {}
    role = g.get("role")
    if role in ("admin", "operator", "viewer"):
        member["le_memberships__role"] = role
    elif role == "superuser":
        qs = qs.filter(is_superuser=True)
    elif role == "none":
        qs = qs.filter(le_memberships__isnull=True, is_superuser=False)
    site = g.get("site")
    if site == "all":
        member.update({"le_memberships__isnull": False, "le_memberships__site__isnull": True})
    elif site:
        if not site.isdigit():
            return qs.none()
        member["le_memberships__site__pk"] = site
    if member:
        qs = qs.filter(**member)
    return qs.distinct()


@admin_required
def users(request):
    qs = _filtered_users(request)
    page = Paginator(qs, _per_page(request)).get_page(request.GET.get("page"))
    for u in page:
        u.eff_role, u.eff_note = services.effective_role(u)
    all_users = User.objects.all()
    ctx = {"page": page, "query": _query(request),
           "sites": Site.objects.filter(tenant_key=settings.LINKEDEYE_TENANT).order_by("name"),
           "k": {"total": all_users.count(), "active": all_users.filter(is_active=True).count(),
                 "inactive": all_users.filter(is_active=False).count(),
                 "never": all_users.filter(last_login__isnull=True).count()}}
    return render(request, "administration/users.html", ctx)


@admin_required
def users_export(request):
    rows = []
    for u in _filtered_users(request)[:EXPORT_LIMIT]:
        role, note = services.effective_role(u)
        ms = "; ".join(f"{m.site.name if m.site else 'All sites'}={m.role}" for m in u.le_memberships.all())
        rows.append([u.username, u.get_full_name(), u.email, "yes" if u.is_active else "no",
                     "yes" if u.is_staff else "no", "yes" if u.is_superuser else "no",
                     u.last_login.isoformat() if u.last_login else "", u.date_joined.isoformat(), role, ms])
    audit(request, "export", object_type="auth.user", rows=len(rows))
    return _csv("users.csv", ["username", "name", "email", "active", "staff", "superuser", "last_login",
                              "date_joined", "effective_role", "memberships"], rows)


@admin_required
def user_create(request):
    if request.method == "POST":
        form = UserCreateForm(request.POST)
        if form.is_valid():
            with transaction.atomic():
                user = form.save(commit=False)
                generated = form.cleaned_data["password_mode"] != "set"
                password = services.generate_password(user) if generated else form.cleaned_data["password1"]
                user.set_password(password)
                user.save()
                site = form.site_obj
                Membership.objects.create(user=user, site=site, role=form.cleaned_data["role"])
                audit(request, "create", user, email=user.email, site=site.name if site else "All sites",
                      role=form.cleaned_data["role"], password="generated" if generated else "set")
            if generated:
                _flash_password(request, user, password)
                messages.success(request, f"Created user “{user.username}”. Copy the generated password now; it is shown only once.")
            else:
                messages.success(request, f"Created user “{user.username}”.")
            return redirect("administration:user_edit", pk=user.pk)
    else:
        form = UserCreateForm()
    return render(request, "administration/user_create.html", {"form": form})


@admin_required
@never_cache
def user_edit(request, pk):
    target = get_object_or_404(_user_qs(), pk=pk)
    if request.method == "POST":
        if _guard_superuser(request, target):
            messages.error(request, "Only a superuser can change another superuser.")
            return redirect("administration:user_edit", pk=target.pk)
        before = {f: getattr(target, f) for f in UserEditForm.Meta.fields}
        form = UserEditForm(request.POST, instance=target)
        if form.is_valid():
            user = form.save()
            changed = {f: getattr(user, f) for f in UserEditForm.Meta.fields if getattr(user, f) != before[f]}
            if changed:
                audit(request, "update", user, **{f: str(v) for f, v in changed.items()})
                messages.success(request, f"Saved “{user.username}”.")
            else:
                messages.info(request, "No changes to save.")
            return redirect("administration:user_edit", pk=user.pk)
    else:
        form = UserEditForm(instance=target)
    role, note = services.effective_role(target)
    ctx = {"target": target, "form": form, "membership_form": MembershipForm(), "password_form": SetPasswordForm(target),
           "memberships": list(target.le_memberships.all()), "role": role, "role_note": note,
           "one_time_password": _pop_password(request, target), "is_self": target.pk == request.user.pk,
           "locked": _guard_superuser(request, target),
           "recent": AuditEvent.objects.filter(Q(actor=target) | Q(object_type="auth.user", object_id=str(target.pk)))[:12],
           "roles": Membership.ROLES}
    return render(request, "administration/user_edit.html", ctx)


class _LockOut(Exception):
    pass


def _apply_membership_change(request, target, change):
    """Run `change()` in a transaction; roll back when it would remove the acting user's own admin console access."""
    try:
        with transaction.atomic():
            result = change()
            if target.pk == request.user.pk:
                services.forget_access_cache(request.user)
                if not services.is_global_admin(request.user):
                    raise _LockOut
    except _LockOut:
        services.forget_access_cache(request.user)
        messages.error(request, "You cannot remove your own admin role on All sites; ask another administrator.")
        return None
    return result


@admin_required
@require_POST
def membership_save(request, pk):
    target = get_object_or_404(User, pk=pk)
    if _guard_superuser(request, target):
        messages.error(request, "Only a superuser can change another superuser.")
        return redirect("administration:user_edit", pk=target.pk)
    form = MembershipForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Choose a valid site and role.")
        return redirect("administration:user_edit", pk=target.pk)
    site, role = form.cleaned_data["site"], form.cleaned_data["role"]

    def change():
        qs = Membership.objects.filter(user=target, site=site) if site else Membership.objects.filter(user=target, site__isnull=True)
        existing = qs.first()
        if existing:
            old = existing.role
            qs.exclude(pk=existing.pk).delete()  # NULL sites are not covered by the unique constraint
            existing.role = role
            existing.save(update_fields=["role"])
            return existing, old
        return Membership.objects.create(user=target, site=site, role=role), None

    result = _apply_membership_change(request, target, change)
    if result is None:
        return redirect("administration:user_edit", pk=target.pk)
    m, old = result
    where = site.name if site else "All sites"
    if old is None:
        audit(request, "membership_add", target, site=where, role=role)
        messages.success(request, f"{target.username} is now {role} on {where}.")
    elif old != role:
        audit(request, "membership_update", target, site=where, role=role, previous_role=old)
        messages.success(request, f"Changed {target.username} on {where} from {old} to {role}.")
    else:
        messages.info(request, f"{target.username} already is {role} on {where}.")
    return redirect("administration:user_edit", pk=target.pk)


@admin_required
@require_POST
def membership_remove(request, pk, mid):
    target = get_object_or_404(User, pk=pk)
    m = get_object_or_404(Membership.objects.select_related("site"), pk=mid, user=target)
    if _guard_superuser(request, target):
        messages.error(request, "Only a superuser can change another superuser.")
        return redirect("administration:user_edit", pk=target.pk)
    where, role = (m.site.name if m.site else "All sites"), m.role
    if _apply_membership_change(request, target, lambda: m.delete() or True) is None:
        return redirect("administration:user_edit", pk=target.pk)
    audit(request, "membership_remove", target, site=where, role=role)
    left = Membership.objects.filter(user=target).exists()
    messages.success(request, f"Removed {role} on {where} from {target.username}."
                     + ("" if left else " With no memberships left the default role applies."))
    return redirect("administration:user_edit", pk=target.pk)


@admin_required
@require_POST
def user_toggle_active(request, pk):
    target = get_object_or_404(User, pk=pk)
    if target.pk == request.user.pk:
        messages.error(request, "You cannot deactivate your own account.")
        return redirect("administration:user_edit", pk=target.pk)
    if _guard_superuser(request, target):
        messages.error(request, "Only a superuser can deactivate another superuser.")
        return redirect("administration:user_edit", pk=target.pk)
    target.is_active = not target.is_active
    target.save(update_fields=["is_active"])
    action = "activate" if target.is_active else "deactivate"
    audit(request, action, target)
    if not target.is_active:
        _end_sessions(target)
    messages.success(request, f"{'Reactivated' if target.is_active else 'Deactivated'} “{target.username}”."
                     + ("" if target.is_active else " The user can no longer sign in."))
    nxt = request.POST.get("next", "")
    if nxt == "list":
        return redirect("administration:users")
    return redirect("administration:user_edit", pk=target.pk)


def _end_sessions(user):
    """Sign the user out everywhere (database sessions only)."""
    try:
        from django.contrib.sessions.models import Session
        now = timezone.now()
        for s in Session.objects.filter(expire_date__gt=now).iterator():
            try:
                if str(s.get_decoded().get("_auth_user_id")) == str(user.pk):
                    s.delete()
            except Exception:
                continue
    except Exception:
        pass


@admin_required
@require_POST
def user_password(request, pk):
    target = get_object_or_404(User, pk=pk)
    if _guard_superuser(request, target):
        messages.error(request, "Only a superuser can change another superuser's password.")
        return redirect("administration:user_edit", pk=target.pk)
    form = SetPasswordForm(target, request.POST)
    if not form.is_valid():
        errs = [str(e) for errs in form.errors.values() for e in errs]
        messages.error(request, "Password not changed: " + " ".join(errs))
        return redirect(reverse("administration:user_edit", args=[target.pk]) + "#password")
    generated = form.cleaned_data["password_mode"] != "set"
    password = services.generate_password(target) if generated else form.cleaned_data["password1"]
    target.set_password(password)
    target.save(update_fields=["password"])
    if target.pk == request.user.pk:
        update_session_auth_hash(request, target)
    else:
        _end_sessions(target)
    audit(request, "set_password", target, password="generated" if generated else "set")
    if generated:
        _flash_password(request, target, password)
        messages.success(request, f"New password generated for “{target.username}”. Copy it now; it is shown only once.")
    else:
        messages.success(request, f"Password changed for “{target.username}”.")
    return redirect("administration:user_edit", pk=target.pk)


# ------------------------------------------------------------------ sites
def _sites_qs():
    return Site.objects.filter(tenant_key=settings.LINKEDEYE_TENANT).annotate(n_members=Count("memberships"))


@admin_required
def sites(request):
    qs = _sites_qs().order_by("name")
    q = request.GET.get("q", "").strip()
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(code__icontains=q) | Q(region__icontains=q))
    crit = request.GET.get("criticality")
    if crit in dict(Site.CRITICALITY):
        qs = qs.filter(criticality=crit)
    usage = services.site_usage()
    page = Paginator(qs, _per_page(request)).get_page(request.GET.get("page"))
    for s in page:
        u = usage.get(s.name, {})
        s.n_urls, s.n_domains = u.get("urls", 0), u.get("domains", 0)
    glob = usage.get("All Sites", {})
    ctx = {"page": page, "query": _query(request), "criticality": Site.CRITICALITY,
           "unmapped": services.unmapped_site_names(), "usage": usage,
           "k": {"total": _sites_qs().count(), "critical": _sites_qs().filter(criticality="critical").count(),
                 "global_urls": glob.get("urls", 0), "global_domains": glob.get("domains", 0)}}
    return render(request, "administration/sites.html", ctx)


@admin_required
def site_create(request):
    form = SiteForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        site = form.save(commit=False)
        site.tenant_key = settings.LINKEDEYE_TENANT
        site.save()
        audit(request, "create", site, code=site.code, region=site.region, timezone=site.timezone,
              criticality=site.criticality)
        messages.success(request, f"Created site “{site.name}”.")
        return redirect("administration:sites")
    return render(request, "administration/site_form.html", {"form": form, "site": None})


@admin_required
def site_edit(request, pk):
    site = get_object_or_404(_sites_qs(), pk=pk)
    old_name = site.name
    fields = SiteForm.Meta.fields
    before = {f: getattr(site, f) for f in fields}
    form = SiteForm(request.POST or None, instance=site)
    if request.method == "POST" and form.is_valid():
        site = form.save()
        changed = {f: getattr(site, f) for f in fields if getattr(site, f) != before[f]}
        if changed:
            audit(request, "update", site, **{f: str(v) for f, v in changed.items()},
                  **({"previous_name": old_name} if "name" in changed else {}))
            messages.success(request, f"Saved site “{site.name}”.")
            if "name" in changed:
                u = services.site_usage().get(old_name, {})
                if u.get("urls") or u.get("domains"):
                    messages.warning(request, f"{u.get('urls', 0)} URL check(s) and {u.get('domains', 0)} domain(s) still "
                                              f"refer to “{old_name}”; update them in their modules.")
        else:
            messages.info(request, "No changes to save.")
        return redirect("administration:sites")
    u = services.site_usage().get(site.name, {})
    ctx = {"form": form, "site": site, "n_urls": u.get("urls", 0), "n_domains": u.get("domains", 0),
           "members": _memberships_qs().filter(site=site).select_related("user")}
    return render(request, "administration/site_form.html", ctx)


@admin_required
@require_POST
def site_delete(request, pk):
    site = get_object_or_404(_sites_qs(), pk=pk)
    if site.n_members:
        messages.error(request, f"“{site.name}” still has {site.n_members} membership(s). Remove them first; "
                                "deleting the site would silently remove those users' access.")
        return redirect("administration:site_edit", pk=site.pk)
    u = services.site_usage().get(site.name, {})
    name = site.name
    audit(request, "delete", site, code=site.code, url_checks=u.get("urls", 0), domains=u.get("domains", 0))
    site.delete()
    note = ""
    if u.get("urls") or u.get("domains"):
        note = f" {u.get('urls', 0)} URL check(s) and {u.get('domains', 0)} domain(s) still use this site name."
    messages.success(request, f"Deleted site “{name}”." + note)
    return redirect("administration:sites")


@admin_required
@require_POST
def sites_bootstrap(request):
    try:
        created, output = services.bootstrap_sites()
    except Exception as e:
        audit(request, "bootstrap", object_type="core.site", result="failed", error=e.__class__.__name__)
        messages.error(request, f"Could not create sites: {e.__class__.__name__}.")
        return redirect("administration:sites")
    audit(request, "bootstrap", object_type="core.site", created=created, output=output)
    if created:
        messages.success(request, f"Created {len(created)} site(s) from existing data: {', '.join(created)}.")
    else:
        messages.info(request, "Every site name used by URL checks and domains already has a site record.")
    return redirect("administration:sites")


# ------------------------------------------------------------------ audit log
def _parse_date(value):
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except (TypeError, ValueError):
        return None


def _filtered_audit(request):
    qs = AuditEvent.objects.all()
    g = request.GET
    q = g.get("q", "").strip()
    if q:
        cond = Q(object_repr__icontains=q) | Q(object_id=q) | Q(actor_name__icontains=q)
        if _looks_like_ip(q):
            cond |= Q(source_ip=q)
        qs = qs.filter(cond)
    for param, field in (("actor", "actor_name"), ("action", "action"), ("type", "object_type"), ("result", "result")):
        v = g.get(param, "").strip()
        if v:
            qs = qs.filter(**{field: v})
    tz = timezone.get_current_timezone()
    d_from, d_to = _parse_date(g.get("from")), _parse_date(g.get("to"))
    if d_from:
        qs = qs.filter(occurred_at__gte=timezone.make_aware(datetime.combine(d_from, time.min), tz))
    if d_to:
        qs = qs.filter(occurred_at__lt=timezone.make_aware(datetime.combine(d_to + timedelta(days=1), time.min), tz))
    return qs, d_from, d_to


def _looks_like_ip(q):
    import ipaddress
    try:
        ipaddress.ip_address(q)
        return True
    except ValueError:
        return False


@admin_required
def audit_log(request):
    qs, d_from, d_to = _filtered_audit(request)
    page = Paginator(qs, _per_page(request)).get_page(request.GET.get("page"))
    base = AuditEvent.objects.order_by()
    ctx = {"page": page, "query": _query(request),
           "actors": base.exclude(actor_name="").values_list("actor_name", flat=True).distinct().order_by("actor_name"),
           "actions": base.values_list("action", flat=True).distinct().order_by("action"),
           "types": base.exclude(object_type="").values_list("object_type", flat=True).distinct().order_by("object_type"),
           "results": base.values_list("result", flat=True).distinct().order_by("result"),
           "date_error": (request.GET.get("from") and not d_from) or (request.GET.get("to") and not d_to),
           "filtered": any(request.GET.get(k) for k in ("q", "actor", "action", "type", "result", "from", "to"))}
    return render(request, "administration/audit.html", ctx)


@admin_required
def audit_export(request):
    qs, _, _ = _filtered_audit(request)
    rows = [[e.occurred_at.isoformat(), e.actor_name, e.action, e.object_type, e.object_id, e.object_repr, e.result,
             e.source_ip or "", _json(e.details)] for e in qs[:EXPORT_LIMIT]]
    audit(request, "export", object_type="core.auditevent", rows=len(rows),
          filters={k: v for k, v in request.GET.items() if k not in ("page", "per")})
    return _csv("audit-log.csv", ["occurred_at", "actor", "action", "object_type", "object_id", "object", "result",
                                  "source_ip", "details"], rows)


def _json(value):
    import json
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return str(value)


# ------------------------------------------------------------------ integrations
@admin_required
def integrations(request):
    items = services.integrations()
    history = IntegrationTest.objects.filter(tenant_key=settings.LINKEDEYE_TENANT)[:15]
    ctx = {"items": items, "history": history,
           "n_configured": sum(1 for i in items if i["configured"]), "n_total": len(items)}
    return render(request, "administration/integrations.html", ctx)


@admin_required
@require_POST
def integration_test(request, key):
    if key not in services.TESTS:
        messages.error(request, "Unknown integration.")
        return redirect("administration:integrations")
    result = services.run_test(request, key)
    audit(request, "test", result, result="ok" if result.ok else "failed", integration=key, message=result.message,
          duration_ms=result.duration_ms)
    (messages.success if result.ok else messages.error)(request, f"{result.get_integration_display()}: {result.message}")
    anchor = {"notify": "webhooks"}.get(key, key)
    return redirect(reverse("administration:integrations") + f"#{anchor}")


# ------------------------------------------------------------------ system health
@admin_required
def health(request):
    return render(request, "administration/health.html", {"h": services.health()})
