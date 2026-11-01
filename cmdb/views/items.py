"""Configuration items and relationships."""
from django.contrib import messages
from django.db.models import Count, Q
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_POST

from core.access import require, visible_sites
from core.audit import audit
from core.events import emit

from .. import csvio, services
from ..forms import CIForm, ImportForm, RelationshipForm
from ..models import HARDWARE_TYPES, SERVICE_TYPES, CIStatus, CIType, Environment, Relationship, RelType
from .common import csv_response, days_class, mark_row_perms, need_site, paginate, perms, query_without_page, safe_next


# ----------------------------------------------------------------------------- list
def filter_items(request, qs):
    g = request.GET
    q = g.get("q", "").strip()
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(ip_address__icontains=q) | Q(owner__icontains=q) | Q(serial__icontains=q)
                       | Q(asset_tag__icontains=q) | Q(business_domain__icontains=q) | Q(vendor__icontains=q)
                       | Q(model__icontains=q) | Q(description__icontains=q))
    for param, field in (("type", "ci_type"), ("status", "status"), ("env", "environment"), ("site", "site")):
        v = g.get(param, "").strip()
        if v:
            qs = qs.filter(**{field: v})
    dom = g.get("domain", "").strip()
    if dom:
        # same membership rule as the heatmap (services.domain_members): business_domain text, or part_of the domain CI
        part_of = Relationship.objects.filter(rel_type=RelType.PART_OF, target__ci_type=CIType.BUSINESS_DOMAIN,
                                              target__name__iexact=dom).values("source_id")
        qs = qs.filter(Q(business_domain__iexact=dom) | Q(ci_type=CIType.BUSINESS_DOMAIN, name__iexact=dom)
                       | Q(pk__in=part_of))
    return qs


@require("view")
def items(request):
    base = services.ci_queryset(request.user)
    if visible_sites(request.user) is None:
        out_f = in_f = None
    else:   # count only links to items the user can see (as the detail and relationships pages do)
        out_f, in_f = Q(outgoing__target__in=base), Q(incoming__source__in=base)
    qs = filter_items(request, base).annotate(n_out=Count("outgoing", filter=out_f, distinct=True),
                                              n_in=Count("incoming", filter=in_f, distinct=True))
    page = paginate(request, qs.order_by("name"))
    health = services.link_health(page.object_list)
    for c in page:
        c.health = health.get(c.pk, "unknown")
    mark_row_perms(request, page)
    counts = dict(base.order_by().values_list("ci_type").annotate(n=Count("pk")))
    status_counts = dict(base.order_by().values_list("status").annotate(n=Count("pk")))
    linked = base.filter(Q(url_checks__isnull=False) | Q(domains__isnull=False)).distinct().count()
    ctx = {
        "page": page, "query": query_without_page(request), "total": base.count(),
        "type_counts": [(v, l, counts.get(v, 0)) for v, l in CIType.choices if counts.get(v)],
        "active": status_counts.get("active", 0), "maintenance": status_counts.get("maintenance", 0),
        "retired": status_counts.get("retired", 0), "linked": linked,
        "relationships": Relationship.objects.filter(source__in=base, target__in=base).count(),
        "types": CIType.choices, "statuses": CIStatus.choices, "envs": Environment.choices,
        "sites": base.order_by("site").values_list("site", flat=True).distinct(),
        "domains": services.domain_names(request.user),
        "filtered": any(request.GET.get(k) for k in ("q", "type", "status", "env", "site", "domain")),
        **perms(request),
    }
    return render(request, "cmdb/items.html", ctx)


# ----------------------------------------------------------------------------- detail
@require("view")
def item_detail(request, pk):
    visible = services.ci_queryset(request.user)
    ci = get_object_or_404(visible.prefetch_related("url_checks", "domains"), pk=pk)
    edges = services.edges_for()
    outgoing = ci.outgoing.select_related("target").order_by("rel_type", "target__name")
    incoming = ci.incoming.select_related("source").order_by("rel_type", "source__name")
    if visible_sites(request.user) is not None:
        # site-scoped users only see (and traverse through) items on their sites
        vis = set(visible.values_list("pk", flat=True))
        edges = [e for e in edges if e[1] in vis and e[2] in vis]
        outgoing, incoming = outgoing.filter(target__in=visible), incoming.filter(source__in=visible)
    outgoing, incoming = list(outgoing), list(incoming)
    impact = services.impacted(ci, edges=edges)
    deps = services.dependencies(ci, edges=edges)
    checks = services.check_rows(ci)
    related = [r.target for r in outgoing] + [r.source for r in incoming] + [r["ci"] for r in impact] + [d for d, _ in deps]
    health = services.link_health([ci] + related)
    for r in impact:
        r["health"] = health.get(r["ci"].pk, "unknown")
    for r in outgoing:
        r.target.health = health.get(r.target_id, "unknown")
    for r in incoming:
        r.source.health = health.get(r.source_id, "unknown")
    mark_row_perms(request, outgoing + incoming, site_of=lambda r: r.source.site)   # delete needs admin on the source
    host = None
    if ci.prometheus_instance:
        from core import prometheus

        from ..heatmap import _fmt, grade, host_metrics
        if prometheus.configured():
            values, err = host_metrics({ci.prometheus_instance})
            v = values.get(ci.prometheus_instance, {})
            host = {"error": err, "connected": True, "metrics": [
                {"label": label, "text": _fmt(col, v.get(col)), "state": grade(col, v.get(col))}
                for col, label in (("cpu", "CPU"), ("memory", "Memory"), ("disk", "Disk"), ("network", "Network"))]}
        else:
            host = {"connected": False}
    incidents = services.recent_incidents([ci.name], limit=6, fingerprints=services.ci_fingerprints([ci]), user=request.user)
    form = RelationshipForm(user=request.user, initial={"source": ci.pk})
    ctx = {
        "ci": ci, "outgoing": outgoing, "incoming": incoming, "impact": impact, "deps": deps, "checks": checks,
        "health": health.get(ci.pk, "unknown"), "health_map": health, "host": host, "incidents": incidents,
        "software": ci.software.all().order_by("name"), "rel_form": form, "rel_types": RelType.choices,
        "impact_services": sum(1 for r in impact if r["ci"].ci_type in ("service", "application", "business_domain")),
        "warranty_cls": days_class(ci.warranty_days), "eol_cls": days_class(ci.eol_days, 180),
        "attributes": sorted((ci.attributes or {}).items()),
        "rel_count": len(outgoing) + len(incoming),
        "on_heatmap": ci.ci_type in SERVICE_TYPES or ci.ci_type == CIType.BUSINESS_DOMAIN,
        "can_edit": services.can_manage(request.user, "operate", ci.site),
        "can_delete": services.can_manage(request.user, "admin", ci.site),
        **perms(request),
    }
    return render(request, "cmdb/item_detail.html", ctx)


# ----------------------------------------------------------------------------- create / edit / delete
def _ci_snapshot(ci):
    return {"name": ci.name, "type": ci.ci_type, "status": ci.status, "site": ci.site, "environment": ci.environment}


@require("operate")
def item_form(request, pk=None):
    ci = get_object_or_404(services.ci_queryset(request.user), pk=pk) if pk else None
    if ci is not None:
        need_site(request, "operate", ci.site)
    before = _ci_snapshot(ci) if ci else None
    if request.method == "POST":
        form = CIForm(request.POST, instance=ci, user=request.user)
        if form.is_valid():
            obj = form.save()
            if ci is None:
                audit(request, "create", obj, **_ci_snapshot(obj))
                emit("cmdb", f"Configuration item {obj.name} created", severity="info", kind="ci_created", site=obj.site,
                     obj=obj, fingerprint=f"cmdb:ci:{obj.pk}", ci=obj.name, ci_type=obj.ci_type)
                messages.success(request, f"Created “{obj.name}”.")
            else:
                changed = sorted(form.changed_data)
                audit(request, "update", obj, fields=changed, **_ci_snapshot(obj))
                if before["status"] != obj.status:
                    emit("cmdb", f"{obj.name} status {before['status']} → {obj.status}", severity="info", kind="ci_status",
                         site=obj.site, obj=obj, fingerprint=f"cmdb:ci:{obj.pk}", ci=obj.name, previous=before["status"],
                         status=obj.status)
                messages.success(request, f"Saved “{obj.name}”.")
            return redirect(safe_next(request, obj.get_absolute_url()))
    else:
        initial = {}
        if ci is None:
            t = request.GET.get("type", "")
            if t in CIType.values:
                initial["ci_type"] = t
            if request.GET.get("domain"):
                initial["business_domain"] = request.GET["domain"][:120]
        form = CIForm(instance=ci, user=request.user, initial=initial)
    return render(request, "cmdb/item_form.html", {
        "form": form, "ci": ci, "domains": services.domain_names(request.user),
        "next": safe_next(request, ""), **perms(request)})


@require_POST
@require("admin")
def item_delete(request, pk):
    ci = get_object_or_404(services.ci_queryset(request.user), pk=pk)
    need_site(request, "admin", ci.site)
    snap = _ci_snapshot(ci)
    rels = ci.outgoing.count() + ci.incoming.count()
    name, site = ci.name, ci.site
    audit(request, "delete", ci, relationships=rels, **snap)
    ci.delete()
    emit("cmdb", f"Configuration item {name} deleted", severity="info", kind="ci_deleted", site=site,
         object_type="cmdb.configurationitem", object_id=pk, fingerprint=f"cmdb:ci:{pk}", ci=name)
    messages.success(request, f"Deleted “{name}” and {rels} relationship(s).")
    return redirect(safe_next(request, reverse("cmdb:items")))


# ----------------------------------------------------------------------------- CSV
@require("view")
def items_export(request, hardware=False):
    qs = filter_items(request, services.ci_queryset(request.user))
    if hardware:
        qs = qs.filter(ci_type__in=HARDWARE_TYPES)
    resp, _w = csv_response("it-assets.csv" if hardware else "configuration-items.csv")
    csvio.write_cis(resp, qs.order_by("name").prefetch_related("url_checks", "domains"))
    return resp


@require("view")
def import_template(request):
    resp = HttpResponse(csvio.template_csv(), content_type="text/csv; charset=utf-8")
    resp["Content-Disposition"] = 'attachment; filename="cmdb-import-template.csv"'
    return resp


@require("operate")
def items_import(request, assets=False):
    back = reverse("cmdb:assets") if assets else reverse("cmdb:items")
    result = None
    if request.method == "POST":
        form = ImportForm(request.POST, request.FILES)
        if form.is_valid():
            result = csvio.import_cis(form.cleaned_data["file"], request.user, form.cleaned_data["update_existing"])
            if not result["errors"]:
                audit(request, "import", object_type="cmdb.configurationitem", created=result["created"],
                      updated=result["updated"], skipped=result["skipped"], file=form.cleaned_data["file"].name[:100])
                messages.success(request, f"Imported {result['created']} new and updated {result['updated']} configuration item(s)"
                                          + (f"; skipped {result['skipped']} existing." if result["skipped"] else "."))
                return redirect(back)
            audit(request, "import", object_type="cmdb.configurationitem", result="failed", errors=len(result["errors"]))
            messages.error(request, f"Nothing was imported: {len(result['errors'])} row(s) need fixing.")
    else:
        form = ImportForm()
    return render(request, "cmdb/import.html", {"form": form, "result": result, "assets": assets, "back": back,
                                                "columns": csvio.COLUMNS, **perms(request)})


# ----------------------------------------------------------------------------- relationships
def filter_relationships(request, qs):
    g = request.GET
    q = g.get("q", "").strip()
    if q:
        qs = qs.filter(Q(source__name__icontains=q) | Q(target__name__icontains=q) | Q(note__icontains=q))
    if g.get("type") in RelType.values:
        qs = qs.filter(rel_type=g["type"])
    if g.get("origin") in ("manual", "discovered"):
        qs = qs.filter(origin=g["origin"])
    if g.get("ci"):
        pk = services.as_pk(g["ci"])
        qs = qs.filter(Q(source_id=pk) | Q(target_id=pk)) if pk else qs.none()
    return qs


def _rel_scope(request):
    cis = services.ci_queryset(request.user)
    return Relationship.objects.filter(source__in=cis, target__in=cis).select_related("source", "target")


@require("view")
def relationships(request):
    base = _rel_scope(request)
    page = paginate(request, filter_relationships(request, base).order_by("source__name", "rel_type", "target__name"))
    mark_row_perms(request, page, site_of=lambda r: r.source.site)
    by_type = dict(base.order_by().values_list("rel_type").annotate(n=Count("pk")))
    ci_pk = services.as_pk(request.GET.get("ci"))
    ci_filter = services.ci_queryset(request.user).filter(pk=ci_pk).first() if ci_pk else None
    source = services.as_pk(request.GET.get("source")) or (ci_filter.pk if ci_filter else None)
    form = RelationshipForm(user=request.user, initial={"source": source})
    return render(request, "cmdb/relationships.html", {
        "ci_filter": ci_filter,
        "page": page, "query": query_without_page(request), "total": base.count(),
        "by_type": [(v, l, by_type.get(v, 0)) for v, l in RelType.choices],
        "discovered": base.filter(origin="discovered").count(), "form": form, "types": RelType.choices,
        "filtered": any(request.GET.get(k) for k in ("q", "type", "origin", "ci")), **perms(request)})


@require_POST
@require("operate")
def relationship_create(request):
    form = RelationshipForm(request.POST, user=request.user)
    fallback = reverse("cmdb:relationships")
    if form.is_valid():
        src, tgt = form.cleaned_data["source"], form.cleaned_data["target"]
        if not (services.can_manage(request.user, "operate", src.site) or services.can_manage(request.user, "operate", tgt.site)):
            messages.error(request, "You cannot change relationships of these items.")
            return redirect(safe_next(request, fallback))
        rel = form.save()
        audit(request, "create", rel, source=src.name, target=tgt.name, rel_type=rel.rel_type, origin=rel.origin)
        messages.success(request, f"Added: {rel}.")
    else:
        errs = "; ".join(e for errs in form.errors.values() for e in errs)
        messages.error(request, f"Relationship not added: {errs}")
    return redirect(safe_next(request, fallback))


@require_POST
@require("admin")
def relationship_delete(request, pk):
    rel = get_object_or_404(_rel_scope(request), pk=pk)
    need_site(request, "admin", rel.source.site)
    text = str(rel)
    audit(request, "delete", rel, source=rel.source.name, target=rel.target.name, rel_type=rel.rel_type)
    rel.delete()
    messages.success(request, f"Removed: {text}.")
    return redirect(safe_next(request, reverse("cmdb:relationships")))


@require("view")
def relationships_export(request):
    resp, w = csv_response("ci-relationships.csv")
    w.writerow(["source", "relationship", "target", "origin", "confidence", "note"])
    for r in filter_relationships(request, _rel_scope(request)).order_by("source__name", "rel_type"):
        w.writerow([csvio.safe(r.source.name), r.rel_type, csvio.safe(r.target.name), r.origin, r.confidence, csvio.safe(r.note)])
    return resp
