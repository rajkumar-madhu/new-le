"""IT assets, software, licenses and lifecycle."""
from collections import Counter
from datetime import date, timedelta

from django.conf import settings
from django.contrib import messages
from django.db.models import Count, Prefetch, Q, Sum
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.http import urlencode
from django.views.decorators.http import require_POST

from core.access import can, require
from core.audit import audit

from .. import csvio, services
from ..forms import LicenseForm, SoftwareForm
from ..models import HARDWARE_TYPES, CIStatus, CIType, ConfigurationItem, Environment, License, Software
from .common import csv_response, days_class, mark_row_perms, paginate, perms, query_without_page, safe_next, site_checker
from .items import filter_items

HW_CHOICES = [(v, l) for v, l in CIType.choices if v in HARDWARE_TYPES]
LIFECYCLE_FILTERS = [("warranty_expired", "Warranty expired"), ("warranty_90", "Warranty ends ≤ 90 days"),
                     ("eol_passed", "Past end of life"), ("eol_180", "EOL ≤ 180 days"),
                     ("eol_due", "Past EOL or EOL ≤ 180 days"), ("no_warranty", "No warranty date")]


def _hardware(request):
    return services.ci_queryset(request.user).filter(ci_type__in=HARDWARE_TYPES)


# ----------------------------------------------------------------------------- IT assets
@require("view")
def assets(request):
    base = _hardware(request)
    today = timezone.localdate()
    qs = filter_items(request, base)
    lf = request.GET.get("lifecycle", "")
    if lf in {k for k, _l in LIFECYCLE_FILTERS}:
        qs = qs.exclude(status="retired")   # lifecycle filters concern live kit, like the KPI cards that link to them
    if lf == "warranty_expired":
        qs = qs.filter(warranty_end__lt=today)
    elif lf == "warranty_90":
        qs = qs.filter(warranty_end__gte=today, warranty_end__lte=today + timedelta(days=90))
    elif lf == "eol_passed":
        qs = qs.filter(eol_date__lt=today)
    elif lf == "eol_180":
        qs = qs.filter(eol_date__gte=today, eol_date__lte=today + timedelta(days=180))
    elif lf == "eol_due":
        qs = qs.filter(eol_date__lte=today + timedelta(days=180))
    elif lf == "no_warranty":
        qs = qs.filter(warranty_end__isnull=True)
    vendor = request.GET.get("vendor", "").strip()
    if vendor:
        qs = qs.filter(vendor__iexact=vendor)
    page = paginate(request, qs.order_by("name"))
    for c in page:
        c.w_cls, c.e_cls = days_class(c.warranty_days), days_class(c.eol_days, 180)
    mark_row_perms(request, page)
    live = base.exclude(status="retired")
    type_counts = dict(base.order_by().values_list("ci_type").annotate(n=Count("pk")))
    ctx = {
        "page": page, "query": query_without_page(request),
        "total": base.count(), "active": base.filter(status="active").count(),
        "warranty_due": live.filter(warranty_end__gte=today, warranty_end__lte=today + timedelta(days=90)).count(),
        "warranty_expired": live.filter(warranty_end__lt=today).count(),
        "eol_due": live.filter(eol_date__lte=today + timedelta(days=180)).count(),
        "value": live.aggregate(s=Sum("cost"))["s"],
        "type_counts": [(v, l, type_counts.get(v, 0)) for v, l in HW_CHOICES],
        "types": HW_CHOICES, "statuses": CIStatus.choices, "envs": Environment.choices,
        "sites": base.order_by("site").values_list("site", flat=True).distinct(),
        "vendors": base.exclude(vendor="").order_by("vendor").values_list("vendor", flat=True).distinct(),
        "lifecycle_filters": LIFECYCLE_FILTERS, "currency": getattr(settings, "CMDB_CURRENCY", ""),
        "filtered": any(request.GET.get(k) for k in ("q", "type", "status", "env", "site", "vendor", "lifecycle")),
        **perms(request),
    }
    return render(request, "cmdb/assets.html", ctx)


# ----------------------------------------------------------------------------- software
def _software(request):
    return Software.objects.filter(tenant_key=settings.LINKEDEYE_TENANT)


def _visible_install_count(request):
    visible = services.ci_queryset(request.user)
    return Count("installs", filter=Q(installs__in=visible), distinct=True)


@require("view")
def software(request):
    base = _software(request)
    qs = base
    q = request.GET.get("q", "").strip()
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(vendor__icontains=q) | Q(version__icontains=q) | Q(category__icontains=q))
    for param in ("vendor", "category"):
        v = request.GET.get(param, "").strip()
        if v:
            qs = qs.filter(**{f"{param}__iexact": v})
    if request.GET.get("licensed") == "no":
        qs = qs.filter(licenses__isnull=True)
    qs = qs.annotate(n_installs=_visible_install_count(request), n_licenses=Count("licenses", distinct=True))
    page = paginate(request, qs.order_by("name", "version"))
    lic = {}
    for l in License.objects.filter(software__in=[s.pk for s in page]).select_related("software"):
        lic.setdefault(l.software_id, []).append(l)
    for s in page:
        s.license_list = lic.get(s.pk, [])
        s.seats = sum(x.seats for x in s.license_list)
        s.over = bool(s.license_list) and s.n_installs > s.seats
    installs_total = ConfigurationItem.software.through.objects.filter(
        software__in=base, configurationitem__in=services.ci_queryset(request.user)).count()
    cats = Counter(c for c in base.values_list("category", flat=True) if c)
    ctx = {
        "page": page, "query": query_without_page(request), "total": base.count(), "installs_total": installs_total,
        "vendors": base.exclude(vendor="").order_by("vendor").values_list("vendor", flat=True).distinct(),
        "categories": sorted(cats), "top_categories": cats.most_common(6),
        "unlicensed": base.filter(licenses__isnull=True).count(),
        "vendor_count": base.exclude(vendor="").values("vendor").distinct().count(),
        "filtered": any(request.GET.get(k) for k in ("q", "vendor", "category", "licensed")),
        **perms(request),
    }
    return render(request, "cmdb/software.html", ctx)


@require("view")
def software_detail(request, pk):
    sw = get_object_or_404(_software(request), pk=pk)
    visible = services.ci_queryset(request.user)
    installs = list(sw.installs.filter(pk__in=visible).order_by("name"))
    health = services.link_health(installs)
    for c in installs:
        c.health = health.get(c.pk, "unknown")
    mark_row_perms(request, installs)
    licenses = list(sw.licenses.all().order_by("product"))
    seats = sum(l.seats for l in licenses)
    may_edit = site_checker(request, "operate")
    candidates = [c for c in visible.exclude(pk__in=[c.pk for c in installs]).exclude(ci_type=CIType.BUSINESS_DOMAIN).order_by("name")
                  if may_edit(c.site)] if can(request.user, "operate") else []
    return render(request, "cmdb/software_detail.html", {
        "sw": sw, "installs": installs, "licenses": licenses, "seats": seats, "used": sw.installs.count(),
        "over": bool(licenses) and sw.installs.count() > seats, "candidates": candidates, **perms(request)})


@require("operate")
def software_form(request, pk=None):
    sw = get_object_or_404(_software(request), pk=pk) if pk else None
    if request.method == "POST":
        form = SoftwareForm(request.POST, instance=sw, user=request.user)
        if form.is_valid():
            obj = form.save()
            audit(request, "create" if sw is None else "update", obj, name=obj.name, version=obj.version,
                  installs=obj.installs.count(), fields=sorted(form.changed_data))
            messages.success(request, f"Saved software “{obj}”.")
            return redirect(safe_next(request, reverse("cmdb:software_detail", args=[obj.pk])))
    else:
        form = SoftwareForm(instance=sw, user=request.user)
    return render(request, "cmdb/form.html", {
        "form": form, "obj": sw, "kind": "Software", "list_url": reverse("cmdb:software"), "list_label": "Software",
        "section": "Assets", "icon": "app", "datalist": ("cmdb-sw-categories", sorted(set(
            _software(request).exclude(category="").values_list("category", flat=True)))), **perms(request)})


@require_POST
@require("operate")
def software_installs(request, pk):
    """Add (ci=<pk>) or remove (remove=<pk>) one install."""
    sw = get_object_or_404(_software(request), pk=pk)
    visible = services.ci_queryset(request.user)
    back = reverse("cmdb:software_detail", args=[sw.pk])
    add, remove = services.as_pk(request.POST.get("ci")), services.as_pk(request.POST.get("remove"))
    if add:
        ci = get_object_or_404(visible, pk=add)
        if not services.can_manage(request.user, "operate", ci.site):
            messages.error(request, "You cannot change items on that site.")
            return redirect(back)
        sw.installs.add(ci)
        audit(request, "update", sw, action_detail="install added", ci=ci.name)
        messages.success(request, f"Recorded {sw} on {ci.name}.")
    elif remove:
        ci = get_object_or_404(visible, pk=remove)
        if not services.can_manage(request.user, "operate", ci.site):
            messages.error(request, "You cannot change items on that site.")
            return redirect(back)
        sw.installs.remove(ci)
        audit(request, "update", sw, action_detail="install removed", ci=ci.name)
        messages.success(request, f"Removed {sw} from {ci.name}.")
    else:
        messages.error(request, "Choose a configuration item.")
    return redirect(safe_next(request, back))


@require_POST
@require("admin")
def software_delete(request, pk):
    sw = get_object_or_404(_software(request), pk=pk)
    name = str(sw)
    audit(request, "delete", sw, name=sw.name, version=sw.version, installs=sw.installs.count())
    sw.delete()
    messages.success(request, f"Deleted software “{name}”. Licenses that used it keep their records.")
    return redirect("cmdb:software")


@require("view")
def software_export(request):
    resp, w = csv_response("software.csv")
    w.writerow(["name", "version", "vendor", "category", "installs", "licensed_seats", "installed_on"])
    visible = services.ci_queryset(request.user).order_by("name").only("pk", "name")
    for s in _software(request).prefetch_related("licenses", Prefetch("installs", queryset=visible, to_attr="visible_installs")
                                                 ).order_by("name", "version"):
        hosts = [c.name for c in s.visible_installs]
        w.writerow([csvio.safe(s.name), csvio.safe(s.version), csvio.safe(s.vendor), csvio.safe(s.category), len(hosts),
                    sum(l.seats for l in s.licenses.all()), csvio.safe(";".join(hosts))])
    return resp


# ----------------------------------------------------------------------------- licenses
def _licenses(request):
    return License.objects.filter(tenant_key=settings.LINKEDEYE_TENANT).select_related("software").annotate(
        _used_count=Count("software__installs", distinct=True))


def _prime(lics):
    for l in lics:
        l._used = l._used_count if l.software_id else 0
    return lics


@require("view")
def licenses(request):
    today = timezone.localdate()
    base = _licenses(request)
    qs = base
    q = request.GET.get("q", "").strip()
    if q:
        qs = qs.filter(Q(product__icontains=q) | Q(vendor__icontains=q) | Q(reference__icontains=q) | Q(software__name__icontains=q))
    st = request.GET.get("state", "")
    all_lics = _prime(list(base))
    if st in ("expired", "over", "expiring", "ok"):
        keep = [l.pk for l in all_lics if l.state == st]
        qs = qs.filter(pk__in=keep)
    page = paginate(request, qs.order_by("product"))
    _prime(page.object_list)
    for l in page:
        l.bar = min(100, round(l.usage_pct))
        l.d_cls = days_class(l.days_left, 60)
    expiring = sorted([l for l in all_lics if l.days_left is not None and l.days_left <= 90], key=lambda l: l.days_left)
    ctx = {
        "page": page, "query": query_without_page(request), "total": len(all_lics),
        "seats": sum(l.seats for l in all_lics), "used": sum(l.used for l in all_lics if l.software_id),
        "over": [l for l in all_lics if l.over_allocated], "expiring": expiring[:10],
        "expiring_count": sum(1 for l in all_lics if l.expiring_within(60)),
        "expired_count": sum(1 for l in all_lics if l.expired),
        "cost": sum((l.cost or 0) for l in all_lics if not l.expired), "today": today,
        "states": [("ok", "Compliant"), ("expiring", "Expiring ≤ 60 days"), ("over", "Over-allocated"), ("expired", "Expired")],
        "filtered": any(request.GET.get(k) for k in ("q", "state")), **perms(request),
    }
    return render(request, "cmdb/licenses.html", ctx)


@require("operate")
def license_form(request, pk=None):
    lic = get_object_or_404(License.objects.filter(tenant_key=settings.LINKEDEYE_TENANT), pk=pk) if pk else None
    if request.method == "POST":
        form = LicenseForm(request.POST, instance=lic)
        if form.is_valid():
            obj = form.save()
            audit(request, "create" if lic is None else "update", obj, product=obj.product, seats=obj.seats,
                  expiry=str(obj.expiry or ""), fields=sorted(form.changed_data))
            msg = f"Saved license “{obj.product}”."
            if obj.over_allocated:
                messages.warning(request, f"{msg} It is over-allocated: {obj.used} installs for {obj.seats} seats.")
            else:
                messages.success(request, msg)
            return redirect(safe_next(request, reverse("cmdb:licenses")))
    else:
        initial = {}
        if lic is None and services.as_pk(request.GET.get("software")):
            initial["software"] = services.as_pk(request.GET["software"])
        form = LicenseForm(instance=lic, initial=initial)
    return render(request, "cmdb/form.html", {
        "form": form, "obj": lic, "kind": "License", "list_url": reverse("cmdb:licenses"), "list_label": "Licenses",
        "section": "Assets", "icon": "key", **perms(request)})


@require_POST
@require("admin")
def license_delete(request, pk):
    lic = get_object_or_404(License.objects.filter(tenant_key=settings.LINKEDEYE_TENANT), pk=pk)
    name = lic.product
    audit(request, "delete", lic, product=lic.product, seats=lic.seats)
    lic.delete()
    messages.success(request, f"Deleted license “{name}”.")
    return redirect("cmdb:licenses")


@require("view")
def licenses_export(request):
    resp, w = csv_response("licenses.csv")
    w.writerow(["product", "vendor", "software", "type", "seats", "used", "expiry", "days_left", "cost", "reference", "state"])
    for l in _prime(list(_licenses(request).order_by("product"))):
        w.writerow([csvio.safe(l.product), csvio.safe(l.vendor), csvio.safe(str(l.software or "")), csvio.safe(l.license_type),
                    l.seats, l.used, l.expiry or "", "" if l.days_left is None else l.days_left,
                    "" if l.cost is None else l.cost, csvio.safe(l.reference), l.state])
    return resp


# ----------------------------------------------------------------------------- lifecycle
WINDOWS = [("30", "Next 30 days", 0, 30), ("90", "31–90 days", 31, 90), ("180", "91–180 days", 91, 180),
           ("overdue", "Overdue", None, -1)]


def lifecycle_events(request, include_licenses=True):
    """Every dated lifecycle milestone: warranty end and EOL of CIs, license expiry."""
    today = timezone.localdate()
    can_edit_lic = can(request.user, "operate")
    out = []
    for c in services.ci_queryset(request.user).exclude(status="retired").filter(
            Q(warranty_end__isnull=False) | Q(eol_date__isnull=False)).order_by("name"):
        for kind, d in (("Warranty end", c.warranty_end), ("End of life", c.eol_date)):
            if d:
                out.append({"kind": kind, "date": d, "days": (d - today).days, "name": c.name, "url": c.get_absolute_url(),
                            "type": c.get_ci_type_display(), "site": c.site, "owner": c.owner, "vendor": c.vendor,
                            "icon": c.icon, "obj": c})
    if include_licenses:
        for l in License.objects.filter(tenant_key=settings.LINKEDEYE_TENANT, expiry__isnull=False):
            out.append({"kind": "License expiry", "date": l.expiry, "days": (l.expiry - today).days, "name": l.product,
                        "url": (reverse("cmdb:license_edit", args=[l.pk]) if can_edit_lic
                                else reverse("cmdb:licenses") + "?" + urlencode({"q": l.product})),
                        "type": "License", "site": "",
                        "owner": l.vendor, "vendor": l.vendor, "icon": "key", "obj": l})
    out.sort(key=lambda e: (e["date"], e["name"].lower()))
    return out


def _bucket(events, key):
    for k, _label, lo, hi in WINDOWS:
        if k == key:
            if lo is None:
                return [e for e in events if e["days"] < 0]
            return [e for e in events if lo <= e["days"] <= hi]
    return []


def _add_months(d, n):
    y, m = divmod(d.month - 1 + n, 12)
    return date(d.year + y, m + 1, 1)


@require("view")
def lifecycle(request):
    events = lifecycle_events(request)
    win = request.GET.get("window", "30")
    if win not in {w[0] for w in WINDOWS}:
        win = "30"
    kind = request.GET.get("kind", "")
    shown = _bucket(events, win)
    if kind in ("Warranty end", "End of life", "License expiry"):
        shown = [e for e in shown if e["kind"] == kind]
    if win == "overdue":
        shown = sorted(shown, key=lambda e: e["days"], reverse=True)
    counts = {k: len(_bucket(events, k)) for k, *_ in WINDOWS}
    # 12-month timeline (stacked bars per month)
    today = timezone.localdate()
    start = date(today.year, today.month, 1)
    months = [_add_months(start, i) for i in range(12)]
    labels = [m.strftime("%b %y") for m in months]
    series = {k: [0] * 12 for k in ("Warranty end", "End of life", "License expiry")}
    for e in events:
        if e["date"] >= start:
            idx = (e["date"].year - start.year) * 12 + e["date"].month - start.month
            if 0 <= idx < 12:
                series[e["kind"]][idx] += 1
    timeline = {"labels": labels, "xLabelEvery": 1, "series": [
        {"name": "Warranty end", "color": "#e08a00", "values": series["Warranty end"]},
        {"name": "End of life", "color": "#d92d20", "values": series["End of life"]},
        {"name": "License expiry", "color": "#7a4fd6", "values": series["License expiry"]}]}
    peak = max((sum(s["values"][i] for s in timeline["series"]) for i in range(12)), default=0)
    if 0 < peak <= 4:   # whole-number axis for small counts
        timeline.update({"yMax": peak, "yTicks": peak})
    hw = _hardware(request).exclude(status="retired")
    ctx = {
        "page": paginate(request, shown, 25), "window": win, "windows": [(k, l, counts[k]) for k, l, *_ in WINDOWS], "kind": kind,
        "timeline": timeline, "has_timeline": any(sum(s["values"]) for s in timeline["series"]),
        "k_warranty_expired": hw.filter(warranty_end__lt=today).count(),
        "k_warranty_90": hw.filter(warranty_end__gte=today, warranty_end__lte=today + timedelta(days=90)).count(),
        "k_eol_passed": hw.filter(eol_date__lt=today).count(),
        "k_eol_180": hw.filter(eol_date__gte=today, eol_date__lte=today + timedelta(days=180)).count(),
        "k_undated": hw.filter(warranty_end__isnull=True, eol_date__isnull=True).count(),
        "k_hw": hw.count(), "query": query_without_page(request), **perms(request),
    }
    return render(request, "cmdb/lifecycle.html", ctx)


@require("view")
def lifecycle_export(request):
    resp, w = csv_response("lifecycle.csv")
    w.writerow(["date", "days_left", "milestone", "item", "type", "site", "owner_or_vendor"])
    for e in lifecycle_events(request):
        w.writerow([e["date"], e["days"], e["kind"], csvio.safe(e["name"]), e["type"], csvio.safe(e["site"]), csvio.safe(e["owner"])])
    return resp
