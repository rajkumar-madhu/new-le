import csv
import re
from datetime import timedelta

from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import Count, F, Q
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_http_methods, require_POST

from core.access import can, require
from core.audit import audit

from . import services
from .forms import RuleForm, RuleTestForm, RunbookForm, TemplateForm, TriggerForm
from .models import REVIEW_AFTER_DAYS, Execution, Template
from .templating import KIND_HELP, KIND_ICONS, ApplyForm, specs_for

EXPORT_LIMIT = 10000


# ------------------------------------------------------------------ helpers
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


def _perms(request):
    return {"can_operate": can(request.user, "operate"), "can_admin": can(request.user, "admin")}


def _who(request):
    return request.user.get_username() if request.user.is_authenticated else ""


def _deny(request, text, fallback):
    messages.error(request, text)
    return redirect(fallback)


def _emit(title, obj, severity="info", message="", **data):
    try:
        from core.events import emit
        emit(source="automation", title=title[:200], severity=severity, message=message, kind="automation_change",
             site=getattr(obj, "site", "") or "", obj=obj, fingerprint=f"automation:{obj._meta.model_name}:{obj.pk}", **data)
    except Exception:  # an event failure must never undo the change
        pass


def _csv(name, header, rows):
    resp = HttpResponse(content_type="text/csv")
    resp["Content-Disposition"] = f'attachment; filename="{name}"'
    w = csv.writer(resp)
    w.writerow(header)
    for r in rows:
        w.writerow([_cell(v) for v in r])
    return resp


def _cell(v):
    """CSV cell; text a spreadsheet would evaluate as a formula (=, +, -, @, tab, CR) is prefixed with a quote."""
    if v is None:
        return ""
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r") and not _is_number(v):
        return "'" + v
    return v


def _is_number(text):
    try:
        float(text)
        return True
    except ValueError:
        return False


def _execution_filters(g, qs):
    """Filter executions by the query parameters in `g` (a QueryDict)."""
    q = g.get("q", "").strip()
    if q:
        qs = qs.filter(Q(trigger__icontains=q) | Q(error__icontains=q) | Q(triggered_by__icontains=q)
                       | Q(rule__name__icontains=q) | Q(result_label__icontains=q))
    if g.get("status") in dict(Execution.STATUSES):
        qs = qs.filter(status=g["status"])
    if g.get("kind") in dict(Execution.KINDS):
        qs = qs.filter(kind=g["kind"])
    if g.get("origin") == "manual":
        qs = qs.filter(rule__isnull=True)
    elif g.get("origin") == "rule":
        qs = qs.filter(rule__isnull=False)
    if g.get("rule", "").isdigit():
        qs = qs.filter(rule_id=int(g["rule"]))
    return qs


def _exec_stats(qs, hours=24):
    since = timezone.now() - timedelta(hours=hours)
    recent = qs.filter(started_at__gte=since)
    agg = recent.aggregate(total=Count("pk"), ok=Count("pk", filter=Q(status="success")),
                           failed=Count("pk", filter=Q(status="failed")), pending=Count("pk", filter=Q(status="pending")))
    done = agg["ok"] + agg["failed"]
    agg["rate"] = (100.0 * agg["ok"] / done) if done else None
    agg["last"] = qs.order_by("-started_at").first()
    return agg


# ------------------------------------------------------------------ runbooks
def _runbook_filtered(request, qs):
    g = request.GET
    q = g.get("q", "").strip()
    if q:
        qs = qs.filter(Q(title__icontains=q) | Q(service__icontains=q) | Q(ci_name__icontains=q) | Q(symptoms__icontains=q)
                       | Q(tags__icontains=q) | Q(owner__icontains=q) | Q(steps__icontains=q))
    if g.get("site"):
        qs = qs.filter(site=g["site"])
    if g.get("service"):
        qs = qs.filter(service=g["service"])
    if g.get("tag"):
        qs = qs.filter(tags__iregex=r"(^|,)\s*" + re.escape(g["tag"].strip()) + r"\s*(,|$)")
    cutoff = timezone.localdate() - timedelta(days=REVIEW_AFTER_DAYS)
    if g.get("review") == "due":
        qs = qs.filter(Q(last_reviewed__isnull=True) | Q(last_reviewed__lt=cutoff))
    elif g.get("review") == "ok":
        qs = qs.filter(last_reviewed__gte=cutoff)
    return qs


@require("view")
def runbooks(request):
    scope = services.runbooks_for(request.user)
    cutoff = timezone.localdate() - timedelta(days=REVIEW_AFTER_DAYS)
    page = Paginator(_runbook_filtered(request, scope).annotate(rule_count=Count("rules")).order_by("title", "pk"), _per_page(request)).get_page(request.GET.get("page"))
    tags = sorted({t for tl in scope.values_list("tags", flat=True) for t in (x.strip() for x in tl.split(",")) if t},
                  key=str.lower)
    return render(request, "automation/runbooks.html", {
        **_perms(request), "page": page, "query": _query(request),
        "total": scope.count(),
        "review_due": scope.filter(Q(last_reviewed__isnull=True) | Q(last_reviewed__lt=cutoff)).count(),
        "linked": scope.filter(rules__isnull=False).distinct().count(),
        "services": sorted(set(scope.exclude(service="").values_list("service", flat=True)), key=str.lower),
        "sites": sorted(set(scope.values_list("site", flat=True)), key=str.lower),
        "tags": tags, "review_days": REVIEW_AFTER_DAYS,
    })


@require("view")
def runbook_export(request):
    rows = _runbook_filtered(request, services.runbooks_for(request.user))[:EXPORT_LIMIT]
    return _csv("runbooks.csv", ["title", "service", "ci_name", "site", "owner", "tags", "last_reviewed", "symptoms", "steps"],
                ([r.title, r.service, r.ci_name, r.site, r.owner, r.tags, r.last_reviewed, r.symptoms, r.steps] for r in rows))


@require("view")
def runbook_detail(request, pk):
    rb = get_object_or_404(services.runbooks_for(request.user), pk=pk)
    rules = services.rules_for(request.user).filter(runbook=rb)
    runs = services.executions_for(request.user).filter(Q(rule__runbook=rb)).select_related("rule")[:10]
    return render(request, "automation/runbook_detail.html", {
        **_perms(request), "rb": rb, "rules": rules, "runs": runs,
        "can_edit": services.can_manage(request.user, "operate", rb.site),
        "can_delete": services.can_manage(request.user, "admin", rb.site),
        "review_days": REVIEW_AFTER_DAYS,
    })


def _runbook_form(request, rb=None):
    sites = services.site_names(request.user)
    if request.method == "POST":
        form = RunbookForm(request.POST, instance=rb, sites=sites)
        if form.is_valid():
            site = form.cleaned_data["site"]
            if not services.can_manage(request.user, "operate", site) or (rb and not services.can_manage(request.user, "operate", rb.site)):
                form.add_error("site", f"You cannot add or change runbooks for “{site}”.")
            else:
                obj = form.save(commit=False)
                created = obj.pk is None
                if created:
                    obj.created_by = _who(request)
                obj.save()
                audit(request, "create" if created else "update", obj, fields=sorted(form.changed_data))
                messages.success(request, f"{'Created' if created else 'Saved'} runbook “{obj.title}”.")
                return redirect(obj.get_absolute_url())
    else:
        form = RunbookForm(instance=rb, sites=sites)
    return render(request, "automation/runbook_form.html", {**_perms(request), "form": form, "rb": rb})


@require("operate")
@require_http_methods(["GET", "POST"])
def runbook_create(request):
    return _runbook_form(request)


@require("operate")
@require_http_methods(["GET", "POST"])
def runbook_edit(request, pk):
    rb = get_object_or_404(services.runbooks_for(request.user), pk=pk)
    if not services.can_manage(request.user, "operate", rb.site):
        return _deny(request, f"You cannot change runbooks for “{rb.site}”.", rb.get_absolute_url())
    return _runbook_form(request, rb)


@require("operate")
@require_POST
def runbook_reviewed(request, pk):
    rb = get_object_or_404(services.runbooks_for(request.user), pk=pk)
    if not services.can_manage(request.user, "operate", rb.site):
        return _deny(request, f"You cannot change runbooks for “{rb.site}”.", rb.get_absolute_url())
    rb.last_reviewed = timezone.localdate()
    rb.save(update_fields=["last_reviewed", "updated_at"])
    audit(request, "review", rb, last_reviewed=str(rb.last_reviewed))
    messages.success(request, f"Marked “{rb.title}” as reviewed today.")
    return redirect(rb.get_absolute_url())


@require("admin")
@require_POST
def runbook_delete(request, pk):
    rb = get_object_or_404(services.runbooks_for(request.user), pk=pk)
    if not services.can_manage(request.user, "admin", rb.site):
        return _deny(request, f"You cannot delete runbooks for “{rb.site}”.", rb.get_absolute_url())
    title = rb.title
    audit(request, "delete", rb, title=title)
    rb.delete()
    messages.success(request, f"Deleted runbook “{title}”.")
    return redirect("automation:runbooks")


# ------------------------------------------------------------------ StackStorm
@require("view")
def stackstorm(request, form=None):
    scope = services.executions_for(request.user).filter(kind="stackstorm")
    qs = _execution_filters(request.GET, scope).select_related("rule")
    page = Paginator(qs, _per_page(request)).get_page(request.GET.get("page"))
    initial = {}
    src = request.GET.get("from", "")
    if src.isdigit():
        prev = scope.filter(pk=int(src)).first()
        if prev:
            initial = {"trigger": prev.trigger, "payload": _pretty(prev.payload)}
    return render(request, "automation/stackstorm.html", {
        **_perms(request), "page": page, "query": _query(request),
        "configured": services.stackstorm_configured(), "st2_url": services.stackstorm_display_url(),
        "api_key_set": bool(getattr(services.settings, "STACKSTORM_API_KEY", "")),
        "can_trigger": services.can_manage(request.user, "operate", "All Sites"),
        "form": form or TriggerForm(initial=initial or {"payload": '{\n  "host": "",\n  "reason": "manual run from LinkedEye"\n}'}),
        "stats": _exec_stats(scope), "statuses": Execution.STATUSES,
        "rule_triggers": services.rules_for(request.user).filter(action="stackstorm"),
    })


def _pretty(value):
    from .templatetags.automation_tags import pretty_json
    return pretty_json(value)


@require("operate")
@require_POST
def stackstorm_trigger(request):
    if not services.can_manage(request.user, "operate", "All Sites"):
        # a manual trigger is not tied to a site, so it needs operate rights across the tenant
        return _deny(request, "Manual StackStorm triggers need the operator role on every site.", "automation:stackstorm")
    form = TriggerForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Fix the errors in the trigger form.")
        return stackstorm(request, form=form)
    ex = services.trigger_stackstorm(form.cleaned_data["trigger"], form.cleaned_data["payload"], triggered_by=_who(request))
    audit(request, "run", ex, object_type="automation.execution", trigger=ex.trigger, status=ex.status,
          result="ok" if ex.status == "success" else "failed")
    _emit(f"StackStorm trigger {ex.trigger}: {ex.status}", ex, message=ex.error or f"HTTP {ex.http_status}",
          trigger=ex.trigger, status=ex.status, http_status=ex.http_status)
    if ex.status == "success":
        messages.success(request, f"Triggered “{ex.trigger}” (HTTP {ex.http_status}).")
    else:
        messages.error(request, f"Trigger “{ex.trigger}” failed: {ex.error}")
    return redirect(reverse("automation:stackstorm") + (f"#exec-{ex.pk}" if ex.pk else ""))


@require("operate")
@require_POST
def stackstorm_test(request):
    ok, text = services.test_stackstorm()
    audit(request, "test_connection", None, object_type="automation.stackstorm", result="ok" if ok else "failed", message=text)
    (messages.success if ok else messages.error)(request, text)
    return redirect("automation:stackstorm")


@require("view")
def execution_detail(request, pk):
    ex = get_object_or_404(services.executions_for(request.user).select_related("rule"), pk=pk)
    event = None
    if ex.event_id:
        from core.models import Event
        event = Event.objects.filter(pk=ex.event_id).first()
    return render(request, "automation/execution_detail.html", {
        **_perms(request), "ex": ex, "event": event,
        "can_rerun": services.can_manage(request.user, "operate", ex.site)
                     and (ex.kind == "webhook" or ex.kind == "stackstorm" and services.stackstorm_configured()),
        "can_retrigger": services.can_manage(request.user, "operate", ex.site),
        "st2_configured": services.stackstorm_configured(),
    })


@require("operate")
@require_POST
def execution_rerun(request, pk):
    ex = get_object_or_404(services.executions_for(request.user), pk=pk)
    if not services.can_manage(request.user, "operate", ex.site):
        return _deny(request, f"You cannot run automation for “{ex.site or 'all sites'}”.", ex.get_absolute_url())
    if ex.kind == "stackstorm":
        new = services.trigger_stackstorm(ex.trigger, ex.payload, triggered_by=_who(request), rule=ex.rule, site=ex.site)
    elif ex.kind == "webhook":
        new = services.post_webhook(ex.trigger, ex.payload, triggered_by=_who(request), rule=ex.rule, site=ex.site)
    else:
        messages.error(request, "Only StackStorm and webhook executions can be re-run.")
        return redirect(ex.get_absolute_url())
    audit(request, "run", new, object_type="automation.execution", rerun_of=ex.pk, status=new.status,
          result="ok" if new.status == "success" else "failed")
    if new.status == "success":
        messages.success(request, f"Re-ran execution #{ex.pk}: success (HTTP {new.http_status}).")
    else:
        messages.error(request, f"Re-run of execution #{ex.pk} failed: {new.error}")
    return redirect(new.get_absolute_url() if new.pk else ex.get_absolute_url())


@require("view")
def execution_export(request):
    qs = _execution_filters(request.GET, services.executions_for(request.user)).select_related("rule")[:EXPORT_LIMIT]
    return _csv("automation-executions.csv",
                ["id", "kind", "trigger", "status", "http_status", "started_at", "finished_at", "duration_ms", "triggered_by",
                 "rule", "site", "result", "error"],
                ([e.pk, e.kind, e.trigger, e.status, e.http_status, e.started_at.isoformat(),
                  e.finished_at.isoformat() if e.finished_at else "", round(e.duration_ms) if e.duration_ms is not None else "",
                  e.triggered_by, e.rule.name if e.rule else "", e.site, e.result_label, e.error] for e in qs))


# ------------------------------------------------------------------ workflows (rules)
@require("view")
def workflows(request):
    rules = services.rules_for(request.user).select_related("runbook")
    q = request.GET.get("q", "").strip()
    shown = rules.filter(Q(name__icontains=q) | Q(description__icontains=q) | Q(match_source__icontains=q)) if q else rules
    if request.GET.get("state") == "on":
        shown = shown.filter(enabled=True)
    elif request.GET.get("state") == "off":
        shown = shown.filter(enabled=False)
    execs = services.executions_for(request.user).filter(rule__isnull=False)
    log_get = request.GET.copy()
    log_get.pop("q", None)   # the search box filters the rules table only
    page = Paginator(_execution_filters(log_get, execs).select_related("rule"), _per_page(request)).get_page(request.GET.get("page"))
    stats = _exec_stats(execs)
    since = timezone.now() - timedelta(hours=24)
    return render(request, "automation/workflows.html", {
        **_perms(request), "rules": shown, "page": page, "query": _query(request), "log_query": _query(request, "q", "state"),
        "rule_total": rules.count(), "rule_enabled": rules.filter(enabled=True).count(),
        "fired24": rules.filter(last_fired_at__gte=since).count(), "stats": stats,
        "statuses": Execution.STATUSES, "all_rules": services.rules_for(request.user).only("pk", "name"),
    })


def _rule_form(request, rule=None):
    sites = services.site_names(request.user)
    runbooks = services.runbooks_for(request.user)
    if request.method == "POST":
        form = RuleForm(request.POST, instance=rule, sites=sites, runbooks=runbooks)
        if form.is_valid():
            site = form.cleaned_data.get("site") or ""
            if not services.can_manage(request.user, "operate", site) or (rule and not services.can_manage(request.user, "operate", rule.site)):
                form.add_error("site", f"You cannot add or change rules for “{site or 'any site'}”.")
            else:
                obj = form.save(commit=False)
                created = obj.pk is None
                if created:
                    obj.created_by = _who(request)
                obj.save()
                audit(request, "create" if created else "update", obj, fields=sorted(form.changed_data), enabled=obj.enabled,
                      rule_action=obj.action)
                messages.success(request, f"{'Created' if created else 'Saved'} rule “{obj.name}”"
                                          f"{'' if obj.enabled else ' (disabled)'}.")
                return redirect(obj.get_absolute_url())
    else:
        form = RuleForm(instance=rule, sites=sites, runbooks=runbooks)
    return render(request, "automation/rule_form.html", {
        **_perms(request), "form": form, "rule": rule, "st2_configured": services.stackstorm_configured(),
    })


@require("operate")
@require_http_methods(["GET", "POST"])
def rule_create(request):
    return _rule_form(request)


@require("operate")
@require_http_methods(["GET", "POST"])
def rule_edit(request, pk):
    rule = get_object_or_404(services.rules_for(request.user), pk=pk)
    if not services.can_manage(request.user, "operate", rule.site):
        return _deny(request, "You cannot change this rule.", rule.get_absolute_url())
    return _rule_form(request, rule)


def _sample_initial(request, rule):
    """Pre-fill the test form from ?event=<id> (a real event) or from the rule's own conditions."""
    from core.models import Event
    eid = request.GET.get("event", "")
    if eid.isdigit():
        from core.access import scope_by_site
        ev = scope_by_site(Event.objects.filter(tenant_key=services.tenant()), request.user).filter(pk=int(eid)).first()
        if ev:
            return {"source": ev.source, "severity": ev.severity, "title": ev.title, "message": ev.message, "site": ev.site,
                    "fingerprint": ev.fingerprint}
    return {"source": rule.sources[0] if rule.sources else "urlchecker",
            "severity": "critical" if rule.min_severity == "critical" else "warning" if rule.min_severity == "warning" else "critical",
            "title": f"Example: {rule.title_contains} is Down" if rule.title_contains else "Example check is Down",
            "site": rule.site, "fingerprint": "test:sample"}


def _rule_detail_context(request, rule, test_form=None, result=None):
    from core.access import scope_by_site
    from core.models import Event
    execs = services.executions_for(request.user).filter(rule=rule)
    page = Paginator(execs, _per_page(request, 10)).get_page(request.GET.get("page"))
    recent = scope_by_site(Event.objects.filter(tenant_key=services.tenant()).exclude(source="automation"), request.user)
    if rule.sources:
        recent = recent.filter(source__in=rule.sources)
    return {
        **_perms(request), "rule": rule, "page": page, "query": _query(request, "event"),
        "test_form": test_form or RuleTestForm(initial=_sample_initial(request, rule)), "result": result,
        "recent_events": recent[:8], "stats": _exec_stats(execs, hours=24 * 7),
        "can_edit": services.can_manage(request.user, "operate", rule.site),
        "can_delete": services.can_manage(request.user, "admin", rule.site),
    }


@require("view")
def rule_detail(request, pk):
    rule = get_object_or_404(services.rules_for(request.user).select_related("runbook"), pk=pk)
    return render(request, "automation/rule_detail.html", _rule_detail_context(request, rule))


@require("view")
@require_POST
def rule_test(request, pk):
    """Evaluate the rule against a sample event. Without 'run' nothing changes; with 'run' (operators) the action runs."""
    from core.models import Event
    rule = get_object_or_404(services.rules_for(request.user).select_related("runbook"), pk=pk)
    form = RuleTestForm(request.POST)
    if not form.is_valid():
        return render(request, "automation/rule_detail.html", _rule_detail_context(request, rule, form), status=400)
    d = form.cleaned_data
    event = Event(tenant_key=services.tenant(), source=d["source"].strip(), severity=d["severity"], title=d["title"],
                  message=d.get("message", ""), site=d.get("site", ""), fingerprint=d.get("fingerprint", ""), data={})
    checks = rule.explain(event)
    matched = all(ok for _c, ok, _d in checks)
    result = {"checks": checks, "matched": matched, "cooldown": matched and services.in_cooldown(rule, event),
              "ignored": event.source.lower() == "automation", "enabled": rule.enabled}
    if d.get("run"):
        if not services.can_manage(request.user, "operate", rule.site):
            messages.error(request, "You do not have permission to run this rule.")
            return redirect(rule.get_absolute_url())
        if not matched:
            messages.error(request, "The sample event does not match this rule; nothing was run.")
            return render(request, "automation/rule_detail.html", _rule_detail_context(request, rule, form, result))
        execs = services.fire(rule, event, triggered_by=f"{_who(request)} (test)")
        failed = [e for e in execs if e.status == "failed"]
        audit(request, "run", rule, test=True, sample_title=event.title, status="failed" if failed else "success",
              result="failed" if failed else "ok")
        if failed:
            messages.error(request, f"Test run of “{rule.name}” failed: {failed[0].error}")
        else:
            label = ", ".join(e.result_label for e in execs if e.result_label)
            messages.success(request, f"Test run of “{rule.name}” succeeded{(': ' + label) if label else ''}.")
        return redirect(rule.get_absolute_url() + "#executions")
    return render(request, "automation/rule_detail.html", _rule_detail_context(request, rule, form, result))


@require("operate")
@require_POST
def rule_toggle(request, pk):
    rule = get_object_or_404(services.rules_for(request.user), pk=pk)
    nxt = request.POST.get("next", "")
    fallback = reverse("automation:workflows") if nxt == "list" else rule.get_absolute_url()
    if not services.can_manage(request.user, "operate", rule.site):
        return _deny(request, "You cannot change this rule.", fallback)
    rule.enabled = not rule.enabled
    rule.save(update_fields=["enabled", "updated_at"])
    audit(request, "enable" if rule.enabled else "disable", rule)
    _emit(f"Automation rule “{rule.name}” {'enabled' if rule.enabled else 'disabled'}", rule, enabled=rule.enabled)
    messages.success(request, f"Rule “{rule.name}” {'enabled' if rule.enabled else 'disabled'}.")
    return redirect(fallback)


@require("admin")
@require_POST
def rule_delete(request, pk):
    rule = get_object_or_404(services.rules_for(request.user), pk=pk)
    if not services.can_manage(request.user, "admin", rule.site):
        return _deny(request, "You cannot delete this rule.", rule.get_absolute_url())
    name = rule.name
    audit(request, "delete", rule, name=name)
    rule.delete()
    messages.success(request, f"Deleted rule “{name}”. Its execution history is kept.")
    return redirect("automation:workflows")


# ------------------------------------------------------------------ templates
def _kinds():
    return [{"key": k, "label": lbl, "icon": KIND_ICONS[k], "help": KIND_HELP[k]} for k, lbl in Template.KINDS]


@require("view")
def templates(request):
    scope = services.templates_for(request.user)
    qs = scope
    q = request.GET.get("q", "").strip()
    if q:
        qs = qs.filter(Q(name__icontains=q) | Q(description__icontains=q))
    if request.GET.get("kind") in dict(Template.KINDS):
        qs = qs.filter(kind=request.GET["kind"])
    page = Paginator(qs, _per_page(request)).get_page(request.GET.get("page"))
    counts = dict(scope.order_by().values_list("kind").annotate(n=Count("pk")))
    kinds = _kinds()
    for k in kinds:
        k["count"] = counts.get(k["key"], 0)
    return render(request, "automation/templates.html", {
        **_perms(request), "page": page, "query": _query(request), "kinds": kinds, "total": scope.count(),
        "kind_icons": KIND_ICONS,
    })


@require("view")
def template_detail(request, pk):
    t = get_object_or_404(services.templates_for(request.user), pk=pk)
    values = [(s.label, t.values.get(s.key), s.key) for s in specs_for(t.kind)]
    can_edit = services.can_manage_template(request.user, "operate", t)
    unknown = {k: v for k, v in t.values.items() if k not in {s.key for s in specs_for(t.kind)}}
    return render(request, "automation/template_detail.html", {
        **_perms(request), "t": t, "values": values, "unknown": unknown, "kind_help": KIND_HELP.get(t.kind, ""),
        "can_edit": can_edit, "can_delete": services.can_manage_template(request.user, "admin", t),
        "kind_icon": KIND_ICONS.get(t.kind, "template"),
    })


def _template_form(request, t=None, kind=None):
    kind = t.kind if t else kind
    sites = services.site_names(request.user)
    if request.method == "POST":
        form = TemplateForm(request.POST, instance=t, kind=kind, sites=sites)
        if form.is_valid() and not services.can_manage_template(request.user, "operate", form.values()):
            site = services.template_site(form.values())
            form.add_error("v_site" if "v_site" in form.fields else None,
                           f"You cannot add or change templates for “{site}”: pick a site you operate.")
        if form.is_valid():
            obj = form.save(commit=False)
            created = obj.pk is None
            if created:
                obj.created_by = _who(request)
            obj.save()
            audit(request, "create" if created else "update", obj, kind=obj.kind, fields=sorted(obj.values))
            messages.success(request, f"{'Created' if created else 'Saved'} template “{obj.name}”.")
            return redirect(obj.get_absolute_url())
    else:
        form = TemplateForm(instance=t, kind=kind, sites=sites)
    return render(request, "automation/template_form.html", {
        **_perms(request), "form": form, "t": t, "kind": kind, "kind_label": dict(Template.KINDS)[kind],
        "kind_help": KIND_HELP[kind], "kind_icon": KIND_ICONS[kind],
    })


@require("operate")
@require_http_methods(["GET", "POST"])
def template_create(request):
    kind = request.GET.get("kind") or request.POST.get("kind")
    if kind not in dict(Template.KINDS):
        return render(request, "automation/template_kind.html", {**_perms(request), "kinds": _kinds()})
    return _template_form(request, kind=kind)


@require("operate")
@require_http_methods(["GET", "POST"])
def template_edit(request, pk):
    t = get_object_or_404(services.templates_for(request.user), pk=pk)
    if not services.can_manage_template(request.user, "operate", t):
        return _deny(request, f"You cannot change templates for “{services.template_site(t)}”.", t.get_absolute_url())
    return _template_form(request, t=t)


@require("operate")
@require_http_methods(["GET", "POST"])
def template_apply(request, pk):
    t = get_object_or_404(services.templates_for(request.user), pk=pk)
    sites = services.site_names(request.user)
    if request.method == "POST":
        form = ApplyForm(request.POST, kind=t.kind, defaults=t.values, sites=sites)
        if form.is_valid():
            values = form.values()
            site = values.get("site", "")
            if not services.can_manage(request.user, "operate", site):
                form.add_error("site" if "site" in form.fields else None, f"You cannot create records for “{site or 'all sites'}”.")
            else:
                try:
                    obj, url, label = services.apply_template(t, values, request.user)
                except services.ApplyError as e:
                    for k, msg in e.errors.items():
                        form.add_error(k if k in form.fields else None, msg)
                except Exception as e:  # the other module failed: show it, never a stack trace
                    form.add_error(None, f"Could not apply the template: {e.__class__.__name__}.")
                else:
                    Template.objects.filter(pk=t.pk).update(applied_count=F("applied_count") + 1, last_applied_at=timezone.now())
                    audit(request, "apply", t, created=label, kind=t.kind, object=f"{obj._meta.label_lower}:{obj.pk}")
                    messages.success(request, f"Created {label} from template “{t.name}”.")
                    return redirect(url or t.get_absolute_url())
    else:
        form = ApplyForm(kind=t.kind, defaults=t.values, sites=sites)
    return render(request, "automation/template_apply.html", {
        **_perms(request), "t": t, "form": form, "kind_help": KIND_HELP.get(t.kind, ""),
        "kind_icon": KIND_ICONS.get(t.kind, "template"),
    })


@require("admin")
@require_POST
def template_delete(request, pk):
    t = get_object_or_404(services.templates_for(request.user), pk=pk)
    if not services.can_manage_template(request.user, "admin", t):
        return _deny(request, f"You cannot delete templates for “{services.template_site(t)}”.", t.get_absolute_url())
    name = t.name
    audit(request, "delete", t, name=name, kind=t.kind)
    t.delete()
    messages.success(request, f"Deleted template “{name}”.")
    return redirect("automation:templates")
