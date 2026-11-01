"""Automation: runbooks, StackStorm / webhook executions, event rules (workflows) and record templates."""
import re

from django.conf import settings
from django.core.validators import MaxValueValidator
from django.db import models
from django.urls import reverse
from django.utils import timezone

REVIEW_AFTER_DAYS = 180

SEVERITY_RANK = {"ok": 0, "info": 1, "warning": 2, "critical": 3}


def _tenant():
    return settings.LINKEDEYE_TENANT


def _tags(text):
    return [t.strip() for t in (text or "").split(",") if t.strip()]


# ------------------------------------------------------------------ runbooks
_STEP_START = re.compile(r"^\s*(?:(?:step\s*)?\d{1,3}\s*[.):]|[-*•])\s+", re.IGNORECASE)


def parse_steps(text):
    """Split plain-text steps into a list of steps, each a list of lines.

    A line that starts with "1." / "2)" / "Step 3:" / "-" / "*" starts a new step and its marker is dropped; other
    lines continue the current step (kept as separate lines). When no line carries a marker, every paragraph
    (block separated by a blank line) — or, if there are no blank lines, every line — becomes one step.
    """
    lines = (text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    if not any(_STEP_START.match(ln) for ln in lines):
        blocks, cur = [], []
        has_blank = any(not ln.strip() for ln in lines) and sum(1 for ln in lines if ln.strip()) > 1
        for ln in lines:
            if not ln.strip():
                if cur:
                    blocks.append(cur)
                    cur = []
                continue
            if has_blank:
                cur.append(ln.rstrip())
            else:
                blocks.append([ln.strip()])
        if cur:
            blocks.append(cur)
        return blocks
    steps, preamble = [], []
    for ln in lines:
        m = _STEP_START.match(ln)
        if m:
            steps.append([ln[m.end():].rstrip()])
        elif ln.strip():
            (steps[-1] if steps else preamble).append(ln.rstrip())
    if preamble:
        steps.insert(0, preamble)
    return steps


class Runbook(models.Model):
    tenant_key = models.CharField(max_length=100, db_index=True, default=_tenant)
    title = models.CharField(max_length=200)
    service = models.CharField(max_length=200, blank=True, help_text="Business service or application this runbook is for.")
    ci_name = models.CharField("CI name", max_length=200, blank=True, help_text="CMDB configuration item, if any.")
    site = models.CharField(max_length=100, default="All Sites", db_index=True)
    symptoms = models.TextField(blank=True, help_text="What operators see when this runbook applies (alerts, errors).")
    steps = models.TextField(help_text="One step per line. Lines starting with 1. / 2) / - start a new step; "
                                       "other lines continue the step above.")
    owner = models.CharField(max_length=150, blank=True)
    tags = models.CharField(max_length=200, blank=True, help_text="Comma separated.")
    last_reviewed = models.DateField(null=True, blank=True)
    created_by = models.CharField(max_length=150, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["title"]
        constraints = [models.UniqueConstraint(fields=["tenant_key", "title"], name="automation_runbook_tenant_title_unique")]

    def __str__(self):
        return self.title

    def get_absolute_url(self):
        return reverse("automation:runbook_detail", args=[self.pk])

    @property
    def tag_list(self):
        return _tags(self.tags)

    @property
    def step_list(self):
        return parse_steps(self.steps)

    @property
    def review_due(self):
        if not self.last_reviewed:
            return True
        return (timezone.localdate() - self.last_reviewed).days > REVIEW_AFTER_DAYS

    @property
    def is_example(self):
        return "example" in [t.lower() for t in self.tag_list]


# ------------------------------------------------------------------ rules (event workflows)
class Rule(models.Model):
    SEVERITIES = [("ok", "Any (incl. recoveries)"), ("info", "Info or higher"), ("warning", "Warning or higher"),
                  ("critical", "Critical only")]
    ACTIONS = [("open_incident", "Open incident"), ("stackstorm", "Trigger StackStorm"), ("webhook", "Call webhook"),
               ("link_runbook", "Link runbook")]

    tenant_key = models.CharField(max_length=100, db_index=True, default=_tenant)
    name = models.CharField(max_length=150)
    description = models.CharField(max_length=300, blank=True)
    enabled = models.BooleanField(default=False)
    match_source = models.CharField(max_length=200, blank=True,
                                    help_text="Event source(s), comma separated (e.g. urlchecker, tcpcheck). Blank = any.")
    min_severity = models.CharField(max_length=10, choices=SEVERITIES, default="warning")
    title_contains = models.CharField(max_length=200, blank=True, help_text="Case-insensitive text the event title must contain.")
    site = models.CharField(max_length=100, blank=True, db_index=True, help_text="Only events from this site. Blank = any site.")
    cooldown_minutes = models.PositiveIntegerField(default=15, validators=[MaxValueValidator(10080)],
                                                   help_text="Fire at most once per event fingerprint in this window.")
    action = models.CharField(max_length=20, choices=ACTIONS, default="open_incident")
    action_params = models.JSONField(default=dict, blank=True)
    runbook = models.ForeignKey(Runbook, null=True, blank=True, on_delete=models.SET_NULL, related_name="rules")
    last_fired_at = models.DateTimeField(null=True, blank=True)
    fire_count = models.PositiveIntegerField(default=0)
    created_by = models.CharField(max_length=150, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]
        constraints = [models.UniqueConstraint(fields=["tenant_key", "name"], name="automation_rule_tenant_name_unique")]

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("automation:rule_detail", args=[self.pk])

    @property
    def sources(self):
        return [s.lower() for s in _tags(self.match_source)]

    @property
    def params(self):
        return self.action_params if isinstance(self.action_params, dict) else {}

    @property
    def is_example(self):
        return self.description.lower().startswith("example")

    def explain(self, event):
        """[(criterion, matched, detail)] for every condition, against an Event (or an object with the same fields)."""
        src = str(getattr(event, "source", "") or "").lower()
        sev = str(getattr(event, "severity", "") or "").lower()
        title = str(getattr(event, "title", "") or "")
        site = str(getattr(event, "site", "") or "")
        out = []
        if self.sources:
            out.append(("Source", src in self.sources, f"“{src or '–'}” {'is' if src in self.sources else 'is not'} one of "
                                                       f"{', '.join(self.sources)}"))
        else:
            out.append(("Source", True, "Any source"))
        ok = SEVERITY_RANK.get(sev, -1) >= SEVERITY_RANK.get(self.min_severity, 2)
        out.append(("Severity", ok, f"“{sev or '–'}” vs. {self.get_min_severity_display().lower()}"))
        if self.title_contains:
            hit = self.title_contains.lower() in title.lower()
            out.append(("Title", hit, f"title {'contains' if hit else 'does not contain'} “{self.title_contains}”"))
        else:
            out.append(("Title", True, "Any title"))
        if self.site and self.site != "All Sites":
            out.append(("Site", site == self.site, f"“{site or '–'}” {'=' if site == self.site else '≠'} “{self.site}”"))
        else:
            out.append(("Site", True, "Any site"))
        return out

    def matches(self, event):
        return all(ok for _c, ok, _d in self.explain(event))

    def match_summary(self):
        parts = [", ".join(self.sources) or "any source", self.get_min_severity_display().lower()]
        if self.title_contains:
            parts.append(f"title ~ “{self.title_contains}”")
        if self.site and self.site != "All Sites":
            parts.append(self.site)
        return " · ".join(parts)

    def action_summary(self):
        p = self.params
        if self.action == "open_incident":
            return f"Open {p.get('priority') or 'P3'} incident"
        if self.action == "stackstorm":
            return f"StackStorm: {p.get('trigger') or '–'}"
        if self.action == "webhook":
            return f"Webhook: {p.get('url') or '–'}"
        if self.action == "link_runbook":
            return f"Runbook: {self.runbook.title if self.runbook else '–'}"
        return self.get_action_display()


# ------------------------------------------------------------------ executions
class Execution(models.Model):
    KINDS = [("stackstorm", "StackStorm"), ("webhook", "Webhook"), ("rule", "Rule")]
    STATUSES = [("pending", "Pending"), ("success", "Success"), ("failed", "Failed")]

    tenant_key = models.CharField(max_length=100, db_index=True, default=_tenant)
    kind = models.CharField(max_length=12, choices=KINDS, db_index=True)
    trigger = models.CharField(max_length=500, help_text="StackStorm trigger, webhook URL or rule action.")
    payload = models.JSONField(default=dict, blank=True)
    status = models.CharField(max_length=10, choices=STATUSES, default="pending", db_index=True)
    http_status = models.PositiveSmallIntegerField(null=True, blank=True)
    response_excerpt = models.TextField(blank=True)
    error = models.CharField(max_length=500, blank=True)
    started_at = models.DateTimeField(default=timezone.now, db_index=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    triggered_by = models.CharField(max_length=150, blank=True)
    rule = models.ForeignKey(Rule, null=True, blank=True, on_delete=models.SET_NULL, related_name="executions")
    site = models.CharField(max_length=100, blank=True, db_index=True)
    event_id = models.BigIntegerField(null=True, blank=True)
    fingerprint = models.CharField(max_length=200, blank=True, db_index=True)
    result_url = models.CharField(max_length=300, blank=True, help_text="Link to what the action created (e.g. an incident).")
    result_label = models.CharField(max_length=120, blank=True)

    class Meta:
        ordering = ["-started_at", "-pk"]
        indexes = [models.Index(fields=["tenant_key", "kind", "started_at"]),
                   models.Index(fields=["rule", "fingerprint", "started_at"])]

    def __str__(self):
        return f"{self.get_kind_display()} {self.trigger[:60]} ({self.status})"

    def get_absolute_url(self):
        return reverse("automation:execution_detail", args=[self.pk])

    @property
    def duration_ms(self):
        if not self.finished_at or not self.started_at:
            return None
        return max(0.0, (self.finished_at - self.started_at).total_seconds() * 1000)

    @property
    def badge_key(self):
        """Status word understood by the {% badge %} tag (core/templatetags/le.py)."""
        return {"success": "ok", "failed": "failed", "pending": "in progress"}.get(self.status, "unknown")

    @property
    def status_tone(self):
        return {"success": "ok", "failed": "crit", "pending": "warn"}.get(self.status, "mute")


# ------------------------------------------------------------------ templates
class Template(models.Model):
    KINDS = [("url_check", "URL check"), ("tcp_check", "TCP check"), ("incident", "Incident"), ("notification", "Notification")]

    tenant_key = models.CharField(max_length=100, db_index=True, default=_tenant)
    kind = models.CharField(max_length=20, choices=KINDS, db_index=True)
    name = models.CharField(max_length=150)
    description = models.CharField(max_length=300, blank=True)
    fields = models.JSONField(default=dict, blank=True, help_text="Default values used when the template is applied.")
    applied_count = models.PositiveIntegerField(default=0)
    last_applied_at = models.DateTimeField(null=True, blank=True)
    created_by = models.CharField(max_length=150, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["kind", "name"]
        constraints = [models.UniqueConstraint(fields=["tenant_key", "name"], name="automation_template_tenant_name_unique")]

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("automation:template_detail", args=[self.pk])

    @property
    def values(self):
        return self.fields if isinstance(self.fields, dict) else {}

    @property
    def is_example(self):
        return self.description.lower().startswith("example")
