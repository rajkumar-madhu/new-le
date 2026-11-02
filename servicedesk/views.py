"""Service Desk pages: incidents overview, ticket lists (all kinds), problems, changes, the service catalog,
ticket detail with workflow actions, create/edit forms and SLA policies.

Permissions (core.access): everyone signed in can view; creating, commenting, assigning and moving tickets
through their workflow needs `operate` on the ticket's site; deleting needs `admin`. Every mutation is a
CSRF-protected POST that writes an audit row, adds a message and redirects."""
import csv
from datetime import timedelta

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_POST

from core.access import can, require, scope_by_site
from core.audit import audit

from . import services, sla, stats
from . import workflow as wf
from .forms import (DEFAULT_CATEGORIES, MAX_PK, MAX_USER_PK, CatalogItemForm, CommentForm, RequestForm, SlaPolicyForm,
                    TicketForm, assignable_users, operable, parse_pk, user_label)
from .models import CatalogItem, SlaPolicy, Ticket, TicketCI

LIST_URL = {"incident": "servicedesk:incidents", "problem": "servicedesk:problems", "change": "servicedesk:changes",
            "request": "servicedesk:tickets"}
INCIDENT_TABS = [("", "Overview"), ("all", "All Incidents"), ("mine", "My Incidents"), ("unassigned", "Unassigned"),
                 ("major", "Major Incidents"), ("sla", "SLA Breaches")]
KIND_TABS = [("", "All Tickets"), ("incident", "Incidents"), ("problem", "Problems"), ("change", "Changes"),
             ("request", "Service Requests")]


# ---------------------------------------------------------------- helpers
def _tenant():
    return settings.LINKEDEYE_TENANT


def _visible(request):
    """Tickets of this tenant on the user's sites (no request filters)."""
    return scope_by_site(Ticket.objects.for_tenant(), request.user)


def _base(request):
    """Visible tickets narrowed by the header site picker (?site=)."""
    qs = _visible(request)
    site = request.GET.get("site", "").strip()
    if site:
        qs = qs.filter(site=site)
    return qs


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


def _can_operate(request, site=None):
    return can(request.user, "operate", site or None)


def apply_filters(request, qs, tab=""):
    """Filter bar + list tabs shared by the lists and the CSV export."""
    g = request.GET
    kind = g.get("kind", "")
    if kind in wf.KIND_LABELS:
        qs = qs.filter(kind=kind)
    if g.get("status") == "open":
        qs = qs.open()
    elif g.get("status") == "done":
        qs = qs.done()
    elif g.get("status") in wf.STATUS_LABELS:
        qs = qs.filter(status=g["status"])
    if g.get("priority") in wf.PRIORITY_LABELS:
        qs = qs.filter(priority=g["priority"])
    for param in ("category", "client"):
        v = g.get(param, "").strip()
        if v == "-":
            qs = qs.filter(**{param: ""})
        elif v:
            qs = qs.filter(**{param: v})
    if g.get("source") in dict(wf.SOURCES):
        qs = qs.filter(source=g["source"])
    a = g.get("assignee", "")
    if a == "me":
        qs = qs.filter(assignee=request.user)
    elif a == "none":
        qs = qs.filter(assignee__isnull=True)
    elif a.isdigit():
        qs = qs.filter(assignee_id=parse_pk(a, MAX_USER_PK) or 0)
    if g.get("sla") == "breached":
        qs = qs.filter(Q(response_breached=True) | Q(resolution_breached=True))
    q = g.get("q", "").strip()
    if q:
        qs = qs.filter(Q(number__iexact=q) | Q(title__icontains=q) | Q(description__icontains=q) | Q(ci_name__icontains=q)
                       | Q(fingerprint__icontains=q) | Q(category__icontains=q) | Q(client__icontains=q))
    if tab == "mine":
        qs = qs.filter(assignee=request.user)
    elif tab == "unassigned":
        qs = qs.open().filter(assignee__isnull=True)
    elif tab == "major":
        qs = qs.filter(priority="P1")
    elif tab == "sla":
        qs = qs.filter(Q(response_breached=True) | Q(resolution_breached=True))
    return qs


def _choices(qs, field):
    return [v for v in qs.order_by(field).values_list(field, flat=True).distinct() if v]


def _assignee_options(qs):
    User = get_user_model()
    ids = set(qs.exclude(assignee__isnull=True).values_list("assignee_id", flat=True).distinct())
    return [(u.pk, user_label(u)) for u in User.objects.filter(pk__in=ids).order_by("first_name", "username")]


def _sites():
    from core.models import Site
    names = list(Site.objects.filter(tenant_key=_tenant()).values_list("name", flat=True))
    used = Ticket.objects.for_tenant().exclude(site="").values_list("site", flat=True).distinct()
    return sorted(set(names) | set(used) | {"All Sites"})


def _ci_names(request):
    """CI names for autocompletion: the CMDB when installed, otherwise names already used on tickets (both limited
    to this tenant and the user's sites)."""
    visible = _visible(request)
    names = set(visible.exclude(ci_name="").values_list("ci_name", flat=True).distinct()[:300])
    names |= set(TicketCI.objects.filter(ticket__in=visible).values_list("ci_name", flat=True).distinct()[:300])
    try:
        from django.apps import apps
        CI = apps.get_model("cmdb", "ConfigurationItem")
        names |= set(scope_by_site(CI.objects.filter(tenant_key=_tenant()), request.user).values_list("name", flat=True)[:500])
    except Exception:  # cmdb absent or not migrated
        pass
    return sorted(names)[:600]


def _ci_url(name):
    """Link to the CI in the CMDB module when it is installed and knows the name."""
    ci = services.find_ci(name) if name else None
    if ci is None:
        return ""
    try:
        return ci.get_absolute_url()
    except Exception:  # CMDB model without a detail URL
        return ""


def _check_pk(pk):
    """404 for a URL id the database cannot hold (it would overflow the driver)."""
    if pk is not None and not 0 < pk <= MAX_PK:
        raise Http404


def _ticket(request, number):
    return get_object_or_404(_visible(request), number=number.upper())


def _denied(request, ticket, perm="operate"):
    """None when allowed; otherwise a redirect back to the ticket with an error message."""
    if can(request.user, perm, ticket.site_scope):
        return None
    messages.error(request, "You do not have permission to do that for tickets on this site.")
    return redirect(ticket)


def _range_ctx(request):
    days = stats.parse_range(request.GET.get("range"))
    return days, stats.RANGES


def _row_actions_ctx(request):
    return {"can_operate": _can_operate(request), "can_admin": can(request.user, "admin")}


def _page(request, qs):
    return Paginator(qs, _per_page(request)).get_page(request.GET.get("page"))


# ---------------------------------------------------------------- incidents overview + tabs
def incidents(request):
    tab = request.GET.get("tab", "")
    if tab not in dict(INCIDENT_TABS):
        tab = ""
    base = _base(request).filter(kind="incident")
    client = request.GET.get("client", "").strip()
    scoped = base.filter(client=client) if client and client != "-" else base
    days, ranges = _range_ctx(request)
    ctx = {
        "tab": tab, "tabs": INCIDENT_TABS, "days": days, "ranges": ranges,
        "clients": _choices(base, "client"), "categories": _choices(base, "category"),
        "assignees": _assignee_options(base), "statuses": wf.statuses_for("incident"), "priorities": wf.PRIORITIES,
        "query": _query(request), "tab_query": _query(request, "tab"),
        "open_count": scoped.open().count(), **_row_actions_ctx(request),
    }
    counts = {"mine": scoped.open().filter(assignee=request.user).count(),
              "unassigned": scoped.open().filter(assignee__isnull=True).count(),
              "major": scoped.open().filter(priority="P1").count(),
              "sla": scoped.open().filter(Q(response_breached=True) | Q(resolution_breached=True)).count()}
    ctx["tab_counts"] = counts
    if tab:
        qs = apply_filters(request, scoped, tab).select_related("assignee").order_by("-opened_at", "-pk")
        ctx["page"] = _page(request, qs)
        ctx["tab_label"] = dict(INCIDENT_TABS)[tab]
        return render(request, "servicedesk/incidents.html", ctx)

    d = stats.overview(scoped, days)
    recent = apply_filters(request, scoped.filter(opened_at__gte=d["start"])).select_related("assignee").order_by("-opened_at", "-pk")
    ctx.update({
        "d": d, "recent": recent[:12], "recent_total": recent.count(),
        "major": scoped.open().filter(priority="P1").select_related("assignee").order_by("-opened_at")[:5],
        "filtered": any(request.GET.get(k) for k in ("status", "priority", "category", "assignee", "q")),
    })
    return render(request, "servicedesk/incidents.html", ctx)


# ---------------------------------------------------------------- all tickets
def tickets(request):
    base = _base(request)
    kind = request.GET.get("kind", "")
    qs = apply_filters(request, base).select_related("assignee").order_by("-opened_at", "-pk")
    kind_counts = dict(base.open().values_list("kind").annotate(n=Count("pk")).order_by())
    statuses = wf.statuses_for(kind) if kind in wf.FLOW else wf.STATUSES
    ctx = {
        "page": _page(request, qs), "kind": kind, "kind_tabs": KIND_TABS, "kind_counts": kind_counts,
        "show_site": base.exclude(site__in=["", "All Sites"]).exists(),
        "statuses": statuses, "priorities": wf.PRIORITIES, "sources": wf.SOURCES,
        "categories": _choices(base, "category"), "clients": _choices(base, "client"), "assignees": _assignee_options(base),
        "query": _query(request), "kind_query": _query(request, "kind", "status"),
        "kpi": {
            "open": base.open().count(),
            "unassigned": base.open().filter(assignee__isnull=True).count(),
            "breached": base.open().filter(Q(response_breached=True) | Q(resolution_breached=True)).count(),
            "today": base.filter(opened_at__gte=timezone.now() - timedelta(hours=24)).count(),
            "resolved7": base.filter(resolved_at__gte=timezone.now() - timedelta(days=7)).count(),
        },
        **_row_actions_ctx(request),
    }
    return render(request, "servicedesk/tickets.html", ctx)


def export_csv(request):
    qs = apply_filters(request, _base(request), request.GET.get("tab", "")).select_related("assignee", "problem")
    resp = HttpResponse(content_type="text/csv")
    kind = request.GET.get("kind", "")
    kind = kind if kind in wf.KIND_LABELS else ""   # never put raw query text into a response header
    resp["Content-Disposition"] = f'attachment; filename="{kind or "ticket"}s-{timezone.localdate():%Y%m%d}.csv"'
    w = csv.writer(resp)
    w.writerow(["number", "kind", "title", "status", "priority", "category", "client", "site", "assignee", "reporter",
                "ci", "source", "opened", "acknowledged", "resolved", "closed", "response_due", "resolution_due",
                "response_breached", "resolution_breached", "problem", "planned_start", "planned_end"])

    def ts(v):
        return timezone.localtime(v).strftime("%Y-%m-%d %H:%M") if v else ""

    def safe(v):  # neutralise spreadsheet formulas in user-entered text
        v = str(v or "")
        return "'" + v if v[:1] in ("=", "+", "-", "@", "\t", "\r") else v

    for t in qs.order_by("-opened_at")[:20000]:
        w.writerow([t.number, t.kind, safe(t.title), t.get_status_display(), t.priority, safe(t.category), safe(t.client),
                    safe(t.site), user_label(t.assignee) if t.assignee else "", safe(t.reporter_name), safe(t.ci_name),
                    t.source, ts(t.opened_at), ts(t.acknowledged_at), ts(t.resolved_at), ts(t.closed_at),
                    ts(t.response_due), ts(t.resolution_due), t.response_breached, t.resolution_breached,
                    t.problem.number if t.problem_id else "", ts(t.planned_start), ts(t.planned_end)])
    return resp


# ---------------------------------------------------------------- problems
def problems(request):
    base = _base(request).filter(kind="problem")
    qs = (apply_filters(request, base).select_related("assignee")
          .annotate(n_incidents=Count("incidents", distinct=True),
                    n_open_incidents=Count("incidents", filter=~Q(incidents__status__in=wf.DONE), distinct=True))
          .order_by("-opened_at", "-pk"))
    ctx = {
        "page": _page(request, qs), "statuses": wf.statuses_for("problem"), "priorities": wf.PRIORITIES,
        "categories": _choices(base, "category"), "assignees": _assignee_options(base), "query": _query(request),
        "kpi": {
            "open": base.open().count(),
            "investigating": base.filter(status="investigating").count(),
            "known_error": base.filter(status="known_error").count(),
            "linked": _visible(request).filter(problem__in=base.open(), kind="incident").count(),
            "resolved30": base.filter(resolved_at__gte=timezone.now() - timedelta(days=30)).count(),
        },
        **_row_actions_ctx(request),
    }
    return render(request, "servicedesk/problems.html", ctx)


# ---------------------------------------------------------------- changes
def changes(request):
    base = _base(request).filter(kind="change")
    approval = request.GET.get("approval", "")
    qs = apply_filters(request, base)
    approval_status = {"not_submitted": ["draft"], "pending": ["submitted"], "rejected": ["rejected"],
                       "approved": ["approved", "scheduled", "implemented", "closed"]}
    if approval in approval_status:
        qs = qs.filter(status__in=approval_status[approval])
    window = request.GET.get("window", "")
    now = timezone.now()
    if window == "upcoming":
        qs = qs.filter(planned_start__gte=now).exclude(status__in=["rejected", "closed", "implemented"])
    elif window == "now":
        qs = qs.filter(planned_start__lte=now, planned_end__gte=now)
    qs = qs.select_related("assignee", "approved_by").annotate(n_cis=Count("cis")).order_by("-opened_at", "-pk")
    page = _page(request, qs)
    for c in page:
        c.in_window = bool(c.planned_start and c.planned_end and c.planned_start <= now <= c.planned_end
                           and c.status in ("approved", "scheduled"))
    upcoming = (base.filter(status__in=["approved", "scheduled"], planned_end__gte=now).exclude(planned_start__isnull=True)
                .order_by("planned_start")[:6])
    ctx = {
        "page": page, "statuses": wf.statuses_for("change"), "priorities": wf.PRIORITIES, "risks": wf.RISKS,
        "approvals": list(wf.APPROVAL_LABELS.items()), "approval": approval, "window": window,
        "categories": _choices(base, "category"), "assignees": _assignee_options(base), "query": _query(request),
        "upcoming": upcoming, "now": now,
        "kpi": {
            "pending": base.filter(status="submitted").count(),
            "scheduled": base.filter(status="scheduled", planned_start__gte=now, planned_start__lte=now + timedelta(days=7)).count(),
            "in_window": base.filter(status__in=["approved", "scheduled"], planned_start__lte=now, planned_end__gte=now).count(),
            "implemented30": base.filter(status__in=["implemented", "closed"], resolved_at__gte=now - timedelta(days=30)).count(),
            "rejected30": base.filter(status="rejected", closed_at__gte=now - timedelta(days=30)).count(),
        },
        **_row_actions_ctx(request),
    }
    return render(request, "servicedesk/changes.html", ctx)


# ---------------------------------------------------------------- service catalog
def catalog(request):
    items = CatalogItem.objects.filter(tenant_key=_tenant())
    show_all = request.GET.get("all") == "1" and can(request.user, "configure")
    if not show_all:
        items = items.filter(active=True)
    q = request.GET.get("q", "").strip()
    if q:
        items = items.filter(Q(name__icontains=q) | Q(description__icontains=q) | Q(category__icontains=q))
    cat = request.GET.get("category", "")
    if cat:
        items = items.filter(category=cat)
    items = items.annotate(n_open=Count("requests", filter=~Q(requests__status__in=wf.DONE)),
                           n_total=Count("requests"))
    my_requests = (_visible(request).filter(kind="request", reporter=request.user).select_related("catalog_item")
                   .order_by("-opened_at")[:8])
    ctx = {
        "items": items, "q": q, "category": cat, "show_all": show_all,
        "categories": _choices(CatalogItem.objects.filter(tenant_key=_tenant(), active=True), "category"),
        "my_requests": my_requests,
        "open_requests": _base(request).filter(kind="request").open().count(),
        "can_operate": _can_operate(request), "can_configure": can(request.user, "configure"),
        "can_admin": can(request.user, "admin"),
    }
    return render(request, "servicedesk/catalog.html", ctx)


@require("configure")
def catalog_edit(request, pk=None):
    _check_pk(pk)
    item = get_object_or_404(CatalogItem, tenant_key=_tenant(), pk=pk) if pk else None
    form = CatalogItemForm(request.POST or None, instance=item)
    if request.method == "POST" and form.is_valid():
        obj = form.save(commit=False)
        obj.tenant_key = _tenant()
        obj.save()
        audit(request, "update" if item else "create", obj, name=obj.name, active=obj.active)
        messages.success(request, f"Saved catalog item “{obj.name}”.")
        return redirect("servicedesk:catalog")
    return render(request, "servicedesk/catalog_form.html", {
        "form": form, "item": item,
        "categories": sorted(set(_choices(CatalogItem.objects.filter(tenant_key=_tenant()), "category")) | {"Access", "Hardware", "Software", "Network", "Accounts"}),
    })


@require_POST
@require("admin")
def catalog_delete(request, pk):
    _check_pk(pk)
    item = get_object_or_404(CatalogItem, tenant_key=_tenant(), pk=pk)
    name = item.name
    audit(request, "delete", item, name=name)
    item.delete()   # requests keep their ticket (catalog_item set to NULL)
    messages.success(request, f"Deleted catalog item “{name}”. Existing requests were kept.")
    return redirect("servicedesk:catalog")


@require("operate")
def catalog_request(request, pk):
    _check_pk(pk)
    item = get_object_or_404(CatalogItem, tenant_key=_tenant(), pk=pk, active=True)
    form = RequestForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        site = form.cleaned_data["site"].strip()
        if not can(request.user, "operate", site if site not in ("", "All Sites") else None):
            form.add_error("site", "You cannot raise requests for this site.")
        else:
            t = services.request_from_catalog(item, request.user, details=form.cleaned_data["details"], site=site,
                                              client=form.cleaned_data["client"].strip())
            audit(request, "create", t, number=t.number, kind="request", catalog_item=item.name)
            messages.success(request, f"Request {t.number} raised for “{item.name}”. Target: {item.fulfilment_hours} h.")
            return redirect(t)
    return render(request, "servicedesk/catalog_request.html", {
        "form": form, "item": item, "sites": _sites(), "clients": _choices(_visible(request), "client")})


# ---------------------------------------------------------------- create / edit
def _form_ctx(request, form, kind, ticket=None):
    visible = _visible(request)
    return {"form": form, "kind": kind, "kind_label": wf.KIND_LABELS[kind], "ticket": ticket, "kinds": wf.KINDS,
            "sites": _sites(), "clients": _choices(visible, "client"),
            "categories": sorted(set(DEFAULT_CATEGORIES) | set(_choices(visible, "category"))),
            "cis": _ci_names(request)}


@require("operate")
def create(request):
    kind = request.POST.get("kind") or request.GET.get("kind") or "incident"
    if kind not in wf.KIND_LABELS:
        kind = "incident"
    initial = {}
    if request.method == "GET":
        for k in ("title", "ci_name", "site", "category", "client"):
            if request.GET.get(k):
                initial[k] = request.GET[k][:200]
        if request.GET.get("priority") in wf.PRIORITY_LABELS:
            initial["priority"] = request.GET["priority"]
    form = TicketForm(request.POST or None, kind=kind, user=request.user, initial=initial, problems=_visible(request))
    if request.method == "POST" and form.is_valid():
        data = {k: v for k, v in form.cleaned_data.items()}
        problem = data.pop("problem", None)
        data["source"] = "catalog" if data.get("catalog_item") else "manual"
        t = services.create_ticket(user=request.user, kind=kind, **data)
        if problem is not None:
            services.link_problem(t, problem, user=request.user)
        audit(request, "create", t, number=t.number, kind=kind, priority=t.priority)
        messages.success(request, f"{t.get_kind_display()} {t.number} created.")
        return redirect(t)
    return render(request, "servicedesk/form.html", _form_ctx(request, form, kind))


@require("operate")
def edit(request, number):
    ticket = _ticket(request, number)
    denied = _denied(request, ticket)
    if denied:
        return denied
    old = {"priority": ticket.priority, "assignee": ticket.assignee, "problem": ticket.problem}
    approved = services.approval_snapshot(ticket)
    form = TicketForm(request.POST or None, instance=ticket, user=request.user, problems=_visible(request))
    if request.method == "POST" and form.is_valid():
        changed = [form.fields[f].label or f for f in form.changed_data if f not in ("priority", "assignee", "problem")]
        obj = form.save(commit=False)
        new_priority, new_assignee = obj.priority, obj.assignee
        new_problem = obj.problem if "problem" in form.fields else old["problem"]
        obj.priority, obj.assignee, obj.problem = old["priority"], old["assignee"], old["problem"]
        obj.save()
        if new_priority != old["priority"]:
            services.set_priority(obj, new_priority, user=request.user)
        if (new_assignee.pk if new_assignee else None) != (old["assignee"].pk if old["assignee"] else None):
            services.assign(obj, new_assignee, user=request.user)
        if "problem" in form.fields and (new_problem.pk if new_problem else None) != (old["problem"].pk if old["problem"] else None):
            services.link_problem(obj, new_problem, user=request.user)
        services.record_edit(obj, [str(c) for c in changed], user=request.user)
        if services.withdraw_approval(obj, approved, user=request.user):
            messages.warning(request, f"{obj.number} changed after approval: it is back to Submitted and needs a new approval.")
        audit(request, "update", obj, number=obj.number, fields=list(form.changed_data))
        messages.success(request, f"{obj.number} updated." if form.changed_data else "No changes to save.")
        return redirect(obj)
    return render(request, "servicedesk/form.html", _form_ctx(request, form, ticket.kind, ticket))


# ---------------------------------------------------------------- detail
def _transitions(request, t):
    """Workflow buttons; no Approve for the requester of a change unless they may approve it themselves."""
    moves = t.transitions()
    if (t.kind == "change" and t.status == "submitted" and t.reporter_id == request.user.pk
            and not services.can_on(request.user, "admin", t.site_scope)):
        moves = [m for m in moves if m[0] != "approved"]
    return moves


def detail(request, number, section=None):
    t = _ticket(request, number)
    if section is not None and section != wf.SECTION[t.kind]:
        if section not in wf.SECTION.values():
            raise Http404
        return redirect(t)   # e.g. /service-desk/incidents/CHG-1001/ -> /service-desk/changes/CHG-1001/
    now = timezone.now()
    site = t.site_scope
    can_op = can(request.user, "operate", site)
    users = assignable_users(site) if can_op else []
    timeline = list(t.timeline.select_related("author").all()[:300])
    flow = wf.FLOW[t.kind]
    happy = [s for s in flow if s != "rejected"] if t.status != "rejected" else ["draft", "submitted", "rejected"]
    pos = happy.index(t.status) if t.status in happy else -1
    steps = [{"key": s, "label": wf.STATUS_LABELS[s], "done": i < pos, "current": i == pos} for i, s in enumerate(happy)]
    ctx = {
        "t": t, "now": now, "timeline": timeline, "steps": steps,
        "transitions": _transitions(request, t) if can_op else [],
        "can_operate": can_op, "can_admin": can(request.user, "admin", site),
        "users": users, "priorities": wf.PRIORITIES,
        "response": sla.response_clock(t, now), "resolution": sla.resolution_clock(t, now), "sla_state": sla.overall(t, now),
        "policy": sla.policy_for(t) if t.kind in wf.SLA_KINDS else None,
        "comment_form": CommentForm(),
        "cis": list(t.cis.all()), "ci_url": _ci_url(t.ci_name),
        "list_url": reverse(LIST_URL[t.kind]),
        "list_label": {"incident": "Incidents", "problem": "Problems", "change": "Changes", "request": "Tickets"}[t.kind],
    }
    if t.kind == "incident":
        # the linked problem may be on a site the user cannot see: show that it exists, never its title or status
        ctx["problem_visible"] = bool(t.problem_id) and _visible(request).filter(pk=t.problem_id).exists()
        # (re)linking writes to the old and the new problem, so it needs operate on their sites as well
        ctx["can_relink"] = can_op and (not t.problem_id or can(request.user, "operate", t.problem.site_scope))
        ctx["problem_choices"] = (operable(_visible(request).filter(kind="problem").exclude(status="closed"), request.user)
                                  .order_by("-opened_at")[:200]) if ctx["can_relink"] else []
        ctx["related"] = (_visible(request).filter(kind="incident").exclude(pk=t.pk)
                          .filter(Q(fingerprint=t.fingerprint) if t.fingerprint else Q(pk__in=[]))
                          .order_by("-opened_at")[:5])
    if t.kind == "problem":
        ctx["linked"] = (scope_by_site(t.incidents.all(), request.user).select_related("assignee").order_by("-opened_at"))
        ctx["hidden_linked"] = t.incidents.count() - len(ctx["linked"])
    if t.kind == "change":
        ctx["ci_names"] = _ci_names(request) if can_op else []
        ctx["conflicts"] = []
        if t.planned_start and t.planned_end:
            ctx["conflicts"] = (_visible(request).filter(kind="change", status__in=["approved", "scheduled"])
                                .exclude(pk=t.pk).filter(planned_start__lt=t.planned_end, planned_end__gt=t.planned_start)
                                .order_by("planned_start")[:5])
    if t.kind == "request" and t.catalog_item_id:
        ctx["item"] = t.catalog_item
    return render(request, "servicedesk/detail.html", ctx)


# ---------------------------------------------------------------- mutations (POST)
@require_POST
@require("operate")
def transition(request, number):
    t = _ticket(request, number)
    denied = _denied(request, t)
    if denied:
        return denied
    target, note = request.POST.get("to", ""), request.POST.get("note", "").strip()[:2000]
    old = t.status
    try:
        services.transition(t, target, user=request.user, note=note)
    except services.WorkflowError as e:
        audit(request, "transition", t, result="denied", from_status=old, to_status=target, reason=str(e))
        messages.error(request, str(e))
        return redirect(t)
    audit(request, "transition", t, number=t.number, from_status=old, to_status=target)
    messages.success(request, f"{t.number} is now {wf.STATUS_LABELS[target]}.")
    return redirect(t)


@require_POST
@require("operate")
def assign(request, number):
    t = _ticket(request, number)
    denied = _denied(request, t)
    if denied:
        return denied
    value = request.POST.get("assignee", "")
    if value == "me":
        user = request.user
    elif value in ("", "none"):
        user = None
    else:
        user = get_user_model().objects.filter(pk=parse_pk(value, MAX_USER_PK) or 0, is_active=True).first()
        if user is None or not can(user, "operate", t.site_scope):
            messages.error(request, "Choose an active user who can work tickets on this site.")
            return redirect(t)
    old = t.assignee
    services.assign(t, user, user=request.user)
    audit(request, "assign", t, number=t.number, old=old.get_username() if old else "", new=user.get_username() if user else "")
    messages.success(request, f"{t.number} assigned to {user_label(user)}." if user else f"{t.number} unassigned.")
    return redirect(t)


@require_POST
@require("operate")
def set_priority(request, number):
    t = _ticket(request, number)
    denied = _denied(request, t)
    if denied:
        return denied
    old, new = t.priority, request.POST.get("priority", "")
    try:
        services.set_priority(t, new, user=request.user)
    except services.WorkflowError as e:
        messages.error(request, str(e))
        return redirect(t)
    audit(request, "priority", t, number=t.number, old=old, new=new)
    messages.success(request, f"{t.number} priority set to {new} ({wf.PRIORITY_LABELS[new]})." if old != new else "Priority unchanged.")
    return redirect(t)


@require_POST
@require("operate")
def comment(request, number):
    t = _ticket(request, number)
    denied = _denied(request, t)
    if denied:
        return denied
    form = CommentForm(request.POST)
    if not form.is_valid():
        messages.error(request, "A comment cannot be empty (max 10,000 characters).")
        return redirect(t)
    entry = services.comment(t, form.cleaned_data["body"], user=request.user)
    audit(request, "comment", t, number=t.number, entry=entry.pk)
    messages.success(request, "Comment added.")
    return redirect(f"{t.get_absolute_url()}#timeline")


@require_POST
@require("operate")
def link(request, number):
    """Incident -> problem (field `problem`, blank unlinks) or problem <- incident (field `incident`)."""
    t = _ticket(request, number)
    denied = _denied(request, t)
    if denied:
        return denied
    try:
        if t.kind == "incident":
            num = request.POST.get("problem", "").strip().upper()
            problem = _visible(request).filter(number=num, kind="problem").first() if num else None
            if num and problem is None:
                raise services.WorkflowError(f"No problem {num} found.")
            old = t.problem if t.problem_id else None
            if (old.pk if old else None) != (problem.pk if problem else None):
                for p in (old, problem):
                    if p is not None and not can(request.user, "operate", p.site_scope):
                        raise services.WorkflowError("You cannot change links of problems on that site.")
            services.link_problem(t, problem, user=request.user)
            audit(request, "link", t, number=t.number, problem=problem.number if problem else "")
            messages.success(request, f"{t.number} linked to {problem.number}." if problem else f"{t.number} unlinked from its problem.")
        elif t.kind == "problem":
            num = request.POST.get("incident", "").strip().upper()
            inc = _visible(request).filter(number=num, kind="incident").first()
            if inc is None:
                raise services.WorkflowError(f"No incident {num or '(blank)'} found.")
            if not can(request.user, "operate", inc.site_scope):
                raise services.WorkflowError("You cannot change incidents on that site.")
            unlink = request.POST.get("unlink") == "1"
            if unlink and inc.problem_id != t.pk:
                raise services.WorkflowError(f"{inc.number} is not linked to {t.number}.")
            if not unlink and inc.problem_id and inc.problem_id != t.pk and not can(request.user, "operate", inc.problem.site_scope):
                raise services.WorkflowError(f"{inc.number} is linked to a problem on a site you cannot change.")
            services.link_problem(inc, None if unlink else t, user=request.user)
            audit(request, "link", inc, number=inc.number, problem="" if unlink else t.number)
            messages.success(request, f"{inc.number} {'unlinked from' if unlink else 'linked to'} {t.number}.")
        else:
            raise services.WorkflowError("Only incidents and problems can be linked.")
    except services.WorkflowError as e:
        messages.error(request, str(e))
    return redirect(t)


@require_POST
@require("operate")
def add_ci(request, number):
    t = _ticket(request, number)
    denied = _denied(request, t)
    if denied:
        return denied
    try:
        ci = services.add_ci(t, request.POST.get("ci_name", ""), user=request.user, note=request.POST.get("note", ""))
    except services.WorkflowError as e:
        messages.error(request, str(e))
        return redirect(t)
    audit(request, "link", t, number=t.number, ci=ci.ci_name)
    messages.success(request, f"Configuration item {ci.ci_name} linked to {t.number}.")
    return redirect(t)


@require_POST
@require("operate")
def remove_ci(request, number, pk):
    t = _ticket(request, number)
    denied = _denied(request, t)
    if denied:
        return denied
    _check_pk(pk)
    ci = get_object_or_404(TicketCI, ticket=t, pk=pk)
    name = ci.ci_name
    services.remove_ci(ci, user=request.user)
    audit(request, "unlink", t, number=t.number, ci=name)
    messages.success(request, f"Configuration item {name} removed from {t.number}.")
    return redirect(t)


@require_POST
@require("admin")
def delete(request, number):
    t = _ticket(request, number)
    denied = _denied(request, t, "admin")
    if denied:
        return denied
    num, kind = t.number, t.kind
    audit(request, "delete", t, number=num, kind=kind, title=t.title)
    t.delete()
    messages.success(request, f"{num} deleted.")
    return redirect(LIST_URL[kind])


# ---------------------------------------------------------------- SLA policies
def sla_policies(request):
    policies = list(SlaPolicy.objects.filter(tenant_key=_tenant()).order_by("priority"))
    can_admin = can(request.user, "admin")
    forms_by_pk = {}
    if request.method == "POST":
        if not can_admin:
            messages.error(request, "Only administrators can change SLA policies.")
            return redirect("servicedesk:sla")
        pk = parse_pk(request.POST.get("pk"))
        p = SlaPolicy.objects.filter(tenant_key=_tenant(), pk=pk).first() if pk else None
        if p is None:
            messages.error(request, "Unknown SLA policy.")
            return redirect("servicedesk:sla")
        form = SlaPolicyForm(request.POST, instance=p, prefix=f"p{p.pk}")
        if form.is_valid():
            form.save()
            audit(request, "update", p, priority=p.priority, response_minutes=p.response_minutes,
                  resolution_minutes=p.resolution_minutes, active=p.active)
            messages.success(request, f"SLA policy for {p.priority} saved. New tickets use it; existing due dates are kept.")
            return redirect("servicedesk:sla")
        forms_by_pk[p.pk] = form
    open_sla = _visible(request).open().filter(kind__in=wf.SLA_KINDS)
    breached = dict(open_sla.filter(Q(response_breached=True) | Q(resolution_breached=True))
                    .values_list("priority").annotate(n=Count("pk")).order_by())
    open_by_p = dict(open_sla.values_list("priority").annotate(n=Count("pk")).order_by())
    rows = [{"p": p, "form": forms_by_pk.get(p.pk) or SlaPolicyForm(instance=p, prefix=f"p{p.pk}"),
             "response": sla.fmt_minutes(p.response_minutes), "resolution": sla.fmt_minutes(p.resolution_minutes),
             "open": open_by_p.get(p.priority, 0), "breached": breached.get(p.priority, 0)} for p in policies]
    return render(request, "servicedesk/sla.html", {"rows": rows, "can_admin": can_admin,
                                                    "missing": [p for p, _ in wf.PRIORITIES if p not in {x.priority for x in policies}]})


def index(request):
    return redirect("servicedesk:incidents")
