"""BOD / EOD market-day validation.

A *mode* (BOD, EOD, ADP) owns an ordered checklist. A *run* validates every enabled checklist item for one
trading date: automated items read the status of an existing URL check, TCP check or domain (optionally
re-running it first); manual items wait for an operator sign-off. Market hours are Indian Standard Time.
"""
from django.conf import settings
from django.db import models
from django.urls import reverse
from django.utils import timezone

GLOBAL_SITES = ("", "All Sites")


class Mode(models.Model):
    CODES = [("BOD", "Beginning of Day"), ("EOD", "End of Day"), ("ADP", "After-Day Processing")]

    tenant_key = models.CharField(max_length=100, db_index=True, default=settings.LINKEDEYE_TENANT)
    code = models.CharField(max_length=3, choices=CODES)
    name = models.CharField(max_length=80)
    description = models.CharField(max_length=300, blank=True)
    site = models.CharField(max_length=100, default="All Sites", help_text="Site the validation belongs to.")
    window_start = models.TimeField(help_text="Window start (IST).")
    window_end = models.TimeField(help_text="Window end (IST).")
    auto_run_time = models.TimeField(null=True, blank=True,
                                     help_text="Start the run automatically at this time (IST) on trading days. Empty = manual only.")
    refresh_checks = models.BooleanField(default=True, help_text="Re-run the referenced checks before validating.")
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["window_start", "code"]
        constraints = [models.UniqueConstraint(fields=["tenant_key", "code"], name="bodeod_mode_tenant_code_unique")]

    def __str__(self):
        return f"{self.code} – {self.name}"

    @property
    def window_label(self):
        return f"{self.window_start:%H:%M}–{self.window_end:%H:%M} IST"


class ChecklistItem(models.Model):
    KINDS = [("url_check", "URL check"), ("tcp_check", "TCP check"), ("domain", "Domain"), ("manual", "Manual")]

    mode = models.ForeignKey(Mode, on_delete=models.CASCADE, related_name="items")
    order = models.PositiveIntegerField(default=10)
    name = models.CharField(max_length=120)
    kind = models.CharField(max_length=10, choices=KINDS, default="url_check")
    ref_name = models.CharField(max_length=253, blank=True,
                                help_text="Name of the URL check / TCP check, or the domain hostname. Empty for manual items.")
    critical = models.BooleanField(default=True, help_text="A critical result on this item fails the whole run.")
    enabled = models.BooleanField(default=True)
    instructions = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["mode", "order", "pk"]
        constraints = [models.UniqueConstraint(fields=["mode", "name"], name="bodeod_item_mode_name_unique")]

    def __str__(self):
        return self.name

    @property
    def automated(self):
        return self.kind != "manual"


class Run(models.Model):
    STATUSES = [("running", "Running"), ("pass", "Pass"), ("warn", "Warning"), ("fail", "Fail")]
    TRIGGERS = [("manual", "Manual"), ("scheduler", "Scheduler")]

    mode = models.ForeignKey(Mode, on_delete=models.CASCADE, related_name="runs")
    trading_date = models.DateField(db_index=True)
    started_at = models.DateTimeField(default=timezone.now, db_index=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    trigger = models.CharField(max_length=10, choices=TRIGGERS, default="manual")
    triggered_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
                                     related_name="bodeod_runs")
    triggered_by_name = models.CharField(max_length=150, blank=True)
    refreshed = models.BooleanField(default=False, help_text="Referenced checks were re-run before validating.")
    status = models.CharField(max_length=10, choices=STATUSES, default="running", db_index=True)
    summary = models.CharField(max_length=300, blank=True)

    class Meta:
        ordering = ["-started_at", "-pk"]
        constraints = [
            # the scheduler starts each mode at most once per trading date
            models.UniqueConstraint(fields=["mode", "trading_date"], condition=models.Q(trigger="scheduler"),
                                    name="bodeod_run_one_scheduled_per_day"),
        ]
        indexes = [models.Index(fields=["mode", "trading_date"])]

    def __str__(self):
        return f"{self.mode.code} run #{self.pk} ({self.trading_date:%d %b %Y})"

    def get_absolute_url(self):
        return reverse("bodeod:detail", args=[self.pk])

    @property
    def duration_seconds(self):
        if not self.finished_at:
            return None
        return max(0.0, (self.finished_at - self.started_at).total_seconds())

    @property
    def by_label(self):
        if self.trigger == "scheduler":
            return "scheduler"
        return self.triggered_by_name or (self.triggered_by.get_username() if self.triggered_by_id else "unknown")


class RunItem(models.Model):
    STATUSES = [("ok", "OK"), ("warning", "Warning"), ("critical", "Critical"), ("unknown", "Unknown"),
                ("pending", "Pending"), ("signed_off", "Signed off")]
    # numeric codes as in the original LinkedEye BOD/EOD screens
    CODES = {"ok": 0, "signed_off": 0, "warning": 1, "critical": 2, "unknown": 3, "pending": 5}

    run = models.ForeignKey(Run, on_delete=models.CASCADE, related_name="results")
    item = models.ForeignKey(ChecklistItem, on_delete=models.SET_NULL, null=True, blank=True, related_name="results")
    # snapshot of the checklist item when the run started (the item may change or be deleted later)
    order = models.PositiveIntegerField(default=0)
    name = models.CharField(max_length=120)
    kind = models.CharField(max_length=10, choices=ChecklistItem.KINDS)
    ref_name = models.CharField(max_length=253, blank=True)
    critical = models.BooleanField(default=True)

    status = models.CharField(max_length=10, choices=STATUSES, default="pending")
    detail = models.CharField(max_length=500, blank=True)
    checked_at = models.DateTimeField(null=True, blank=True)
    signed_off_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
                                      related_name="bodeod_signoffs")
    signed_off_by_name = models.CharField(max_length=150, blank=True)
    signed_off_at = models.DateTimeField(null=True, blank=True)
    note = models.CharField(max_length=500, blank=True)

    class Meta:
        ordering = ["run", "order", "pk"]

    def __str__(self):
        return f"{self.name}: {self.status}"

    @property
    def code(self):
        return self.CODES.get(self.status, 3)

    @property
    def automated(self):
        return self.kind != "manual"


class Holiday(models.Model):
    EXCHANGES = [("ALL", "All exchanges"), ("NSE", "NSE"), ("BSE", "BSE"), ("MCX", "MCX")]
    SOURCES = [("manual", "Added manually"), ("csv", "CSV upload"), ("example", "Example")]

    tenant_key = models.CharField(max_length=100, db_index=True, default=settings.LINKEDEYE_TENANT)
    exchange = models.CharField(max_length=3, choices=EXCHANGES, default="NSE")
    date = models.DateField(db_index=True)
    description = models.CharField(max_length=200)
    source = models.CharField(max_length=10, choices=SOURCES, default="manual")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["date", "exchange"]
        constraints = [models.UniqueConstraint(fields=["tenant_key", "exchange", "date"],
                                               name="bodeod_holiday_tenant_exchange_date_unique")]

    def __str__(self):
        return f"{self.date:%d %b %Y} {self.exchange}: {self.description}"
