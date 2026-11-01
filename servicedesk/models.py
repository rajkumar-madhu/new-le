"""Service desk records: tickets (incidents, problems, changes, service requests), their timeline,
SLA policies per priority and the service catalog."""
from django.conf import settings
from django.db import models, transaction
from django.db.models import F, Max
from django.urls import reverse
from django.utils import timezone

from . import workflow as wf


def _tenant():
    return settings.LINKEDEYE_TENANT


class SlaPolicy(models.Model):
    """Response and resolution targets for one priority."""
    tenant_key = models.CharField(max_length=100, db_index=True, default=_tenant)
    priority = models.CharField(max_length=2, choices=wf.PRIORITIES)
    name = models.CharField(max_length=100)
    response_minutes = models.PositiveIntegerField(help_text="Time allowed until the ticket leaves New")
    resolution_minutes = models.PositiveIntegerField(help_text="Time allowed until the ticket is resolved")
    active = models.BooleanField(default=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["priority"]
        verbose_name = "SLA policy"
        verbose_name_plural = "SLA policies"
        constraints = [models.UniqueConstraint(fields=["tenant_key", "priority"], name="sd_sla_tenant_priority_unique")]

    def __str__(self):
        return f"{self.priority} · {self.name}"


class CatalogItem(models.Model):
    """An orderable service; the Request button turns it into a request ticket."""
    tenant_key = models.CharField(max_length=100, db_index=True, default=_tenant)
    name = models.CharField(max_length=120)
    category = models.CharField(max_length=80, blank=True)
    description = models.TextField(blank=True)
    fulfilment_hours = models.PositiveIntegerField(default=24, help_text="Target time to fulfil a request")
    default_priority = models.CharField(max_length=2, choices=wf.PRIORITIES, default="P4")
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["category", "name"]
        constraints = [models.UniqueConstraint(fields=["tenant_key", "name"], name="sd_catalog_tenant_name_unique")]

    def __str__(self):
        return self.name


class TicketCounter(models.Model):
    """Last number handed out per kind (INC-1001, PRB-1001 …)."""
    tenant_key = models.CharField(max_length=100, default=_tenant)
    kind = models.CharField(max_length=10, choices=wf.KINDS)
    last = models.PositiveIntegerField(default=1000)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["tenant_key", "kind"], name="sd_counter_tenant_kind_unique")]


def next_number(tenant_key, kind):
    """Atomically hand out the next sequence number for a kind (never below existing tickets)."""
    with transaction.atomic():
        floor = Ticket.objects.filter(tenant_key=tenant_key, kind=kind).aggregate(m=Max("seq"))["m"] or 1000
        counter, _ = TicketCounter.objects.get_or_create(tenant_key=tenant_key, kind=kind, defaults={"last": floor})
        TicketCounter.objects.filter(pk=counter.pk).update(last=F("last") + 1)   # serialised by the database
        counter.refresh_from_db(fields=["last"])
        if counter.last <= floor:   # tickets were imported/created behind the counter's back
            counter.last = floor + 1
            TicketCounter.objects.filter(pk=counter.pk).update(last=counter.last)
        return counter.last, f"{wf.PREFIX[kind]}-{counter.last}"


class TicketQuerySet(models.QuerySet):
    def for_tenant(self):
        return self.filter(tenant_key=settings.LINKEDEYE_TENANT)

    def open(self):
        return self.exclude(status__in=wf.DONE)

    def done(self):
        return self.filter(status__in=wf.DONE)


class Ticket(models.Model):
    tenant_key = models.CharField(max_length=100, db_index=True, default=_tenant)
    kind = models.CharField(max_length=10, choices=wf.KINDS, default="incident")
    seq = models.PositiveIntegerField(editable=False, default=0)
    number = models.CharField(max_length=20, editable=False, db_index=True)
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=wf.STATUSES, default="new")
    priority = models.CharField(max_length=2, choices=wf.PRIORITIES, default="P3")
    category = models.CharField(max_length=80, blank=True)
    client = models.CharField(max_length=100, blank=True)
    site = models.CharField(max_length=100, blank=True, db_index=True)
    assignee = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="sd_assigned")
    reporter = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="sd_reported")
    reporter_name = models.CharField(max_length=150, blank=True, help_text="Who/what raised it (user name or module)")
    ci_name = models.CharField("Configuration item", max_length=200, blank=True, db_index=True)
    source = models.CharField(max_length=12, choices=wf.SOURCES, default="manual")
    origin = models.CharField(max_length=40, blank=True, help_text="Module that raised an alert/automation ticket")
    fingerprint = models.CharField(max_length=200, blank=True, db_index=True)
    catalog_item = models.ForeignKey(CatalogItem, on_delete=models.SET_NULL, null=True, blank=True, related_name="requests")
    problem = models.ForeignKey("self", on_delete=models.SET_NULL, null=True, blank=True, related_name="incidents",
                                limit_choices_to={"kind": "problem"}, help_text="Problem record this incident is linked to")
    # problem fields
    root_cause = models.TextField(blank=True)
    workaround = models.TextField(blank=True)
    # change fields
    risk = models.CharField(max_length=6, choices=wf.RISKS, blank=True)
    planned_start = models.DateTimeField(null=True, blank=True)
    planned_end = models.DateTimeField(null=True, blank=True)
    implementation_plan = models.TextField(blank=True)
    backout_plan = models.TextField(blank=True)
    approved_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="sd_approved")
    approved_at = models.DateTimeField(null=True, blank=True)
    resolution = models.TextField(blank=True, help_text="Resolution / fulfilment notes")
    # timestamps
    opened_at = models.DateTimeField(default=timezone.now, db_index=True)
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    closed_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    # SLA
    response_due = models.DateTimeField(null=True, blank=True)
    resolution_due = models.DateTimeField(null=True, blank=True)
    response_breached = models.BooleanField(default=False)
    resolution_breached = models.BooleanField(default=False)

    objects = TicketQuerySet.as_manager()

    class Meta:
        ordering = ["-opened_at", "-pk"]
        constraints = [models.UniqueConstraint(fields=["tenant_key", "number"], name="sd_ticket_tenant_number_unique")]
        indexes = [models.Index(fields=["tenant_key", "kind", "status"]), models.Index(fields=["tenant_key", "kind", "opened_at"])]

    def __str__(self):
        return f"{self.number} {self.title}"

    def save(self, *args, **kwargs):
        adding = self._state.adding
        if not self.status:
            self.status = wf.INITIAL[self.kind]
        if not self.number:
            self.seq, self.number = next_number(self.tenant_key, self.kind)
        if adding and self.response_due is None and self.resolution_due is None:
            from .sla import apply_due_dates
            apply_due_dates(self)
        super().save(*args, **kwargs)

    def get_absolute_url(self):
        """Canonical detail URL under the kind's own section (incidents/, problems/, changes/, tickets/)."""
        return reverse("servicedesk:detail_in", args=[wf.SECTION[self.kind], self.number])

    # ---- presentation helpers
    @property
    def is_open(self):
        return self.status not in wf.DONE

    @property
    def status_tone(self):
        return wf.STATUS_TONE.get(self.status, "mute")

    @property
    def priority_label(self):
        return wf.PRIORITY_LABELS.get(self.priority, self.priority)

    @property
    def priority_tone(self):
        return wf.PRIORITY_TONE.get(self.priority, "mute")

    @property
    def priority_dot(self):
        return wf.PRIORITY_DOT.get(self.priority, False)

    @property
    def breached(self):
        return self.response_breached or self.resolution_breached

    @property
    def approval_state(self):
        return wf.approval_state(self.status) if self.kind == "change" else ""

    @property
    def approval_label(self):
        return wf.APPROVAL_LABELS.get(self.approval_state, "")

    @property
    def approval_tone(self):
        return wf.APPROVAL_TONE.get(self.approval_state, "mute")

    def transitions(self):
        return wf.transitions(self.kind, self.status)

    @property
    def site_scope(self):
        """Site name to check permissions against (None for global tickets)."""
        return self.site if self.site not in ("", "All Sites") else None


class TicketCI(models.Model):
    """A configuration item affected by a ticket (used for changes; incidents carry ci_name)."""
    ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE, related_name="cis")
    ci_name = models.CharField(max_length=200, db_index=True)
    note = models.CharField(max_length=200, blank=True)
    added_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ["ci_name"]
        constraints = [models.UniqueConstraint(fields=["ticket", "ci_name"], name="sd_ticketci_unique")]

    def __str__(self):
        return f"{self.ticket.number} → {self.ci_name}"


class TimelineEntry(models.Model):
    KINDS = [("comment", "Comment"), ("status", "Status change"), ("assignment", "Assignment"), ("priority", "Priority change"),
             ("link", "Link"), ("sla", "SLA"), ("system", "System"), ("edit", "Edit")]

    ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE, related_name="timeline")
    kind = models.CharField(max_length=12, choices=KINDS, default="comment")
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    author_name = models.CharField(max_length=150, blank=True)
    body = models.TextField(blank=True)
    old_value = models.CharField(max_length=100, blank=True)
    new_value = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        ordering = ["-created_at", "-pk"]
        verbose_name_plural = "timeline entries"

    def __str__(self):
        return f"{self.ticket.number} {self.kind}: {self.body[:40]}"

    @property
    def who(self):
        if self.author_id:
            return self.author.get_full_name() or self.author.get_username()
        return self.author_name or "system"
