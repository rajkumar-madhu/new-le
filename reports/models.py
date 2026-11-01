from datetime import datetime, time, timedelta

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import MaxValueValidator, MinValueValidator, validate_email
from django.db import models
from django.utils import timezone


def _tenant():
    return settings.LINKEDEYE_TENANT


class ScheduledReport(models.Model):
    """A report e-mailed as CSV on a schedule (sent by the `reports.scheduled` job)."""

    FREQUENCIES = [("daily", "Daily"), ("weekly", "Weekly (Monday)"), ("monthly", "Monthly (1st)")]

    tenant_key = models.CharField(max_length=100, db_index=True, default=_tenant)
    name = models.CharField(max_length=120)
    report_key = models.CharField("Report", max_length=40)
    window_days = models.PositiveSmallIntegerField("Period (days)", default=7,
                                                   validators=[MinValueValidator(1), MaxValueValidator(366)])
    site = models.CharField(max_length=100, blank=True, help_text="Limit to one site; blank = every site the owner can see")
    frequency = models.CharField(max_length=8, choices=FREQUENCIES, default="weekly")
    send_hour = models.PositiveSmallIntegerField("Send at (hour, local time)", default=7,
                                                 validators=[MaxValueValidator(23)])
    recipients = models.TextField(help_text="E-mail addresses separated by commas or new lines")
    enabled = models.BooleanField(default=True)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True,
                              related_name="scheduled_reports",
                              help_text="Rows are limited to the sites this user can see")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    next_run_at = models.DateTimeField(null=True, blank=True, db_index=True)
    last_run_at = models.DateTimeField(null=True, blank=True)
    last_status = models.CharField(max_length=10, blank=True)
    last_error = models.CharField(max_length=500, blank=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    def recipient_list(self):
        raw = self.recipients.replace("\n", ",").replace(";", ",")
        return [r.strip() for r in raw.split(",") if r.strip()]

    def clean(self):
        from . import registry
        errors = {}
        if self.report_key not in registry.REPORTS:
            errors["report_key"] = "Unknown report."
        emails = self.recipient_list()
        if not emails:
            errors["recipients"] = "Add at least one e-mail address."
        elif len(emails) > 50:
            errors["recipients"] = "At most 50 recipients."
        else:
            for e in emails:
                try:
                    validate_email(e)
                except ValidationError:
                    errors["recipients"] = f"“{e}” is not a valid e-mail address."
                    break
        if errors:
            raise ValidationError(errors)

    def compute_next_run(self, after=None):
        """Next send time strictly after `after` (default now), in the server's local time zone."""
        after = after or timezone.now()
        local = timezone.localtime(after)
        day = local.date()
        for _ in range(400):
            cand = timezone.make_aware(datetime.combine(day, time(self.send_hour)))
            if cand > after and (
                self.frequency == "daily"
                or (self.frequency == "weekly" and day.weekday() == 0)
                or (self.frequency == "monthly" and day.day == 1)
            ):
                return cand
            day += timedelta(days=1)
        return None

    def save(self, *args, **kwargs):
        if self.enabled and self.next_run_at is None:
            self.next_run_at = self.compute_next_run()
        if not self.enabled:
            self.next_run_at = None
        super().save(*args, **kwargs)


class ReportRun(models.Model):
    """One generated report: a download, a preview export or a scheduled e-mail. The CSV itself is not stored."""

    STATUSES = [("ok", "Delivered"), ("empty", "No rows"), ("failed", "Failed")]
    CHANNELS = [("download", "Download"), ("email", "E-mail")]

    tenant_key = models.CharField(max_length=100, db_index=True, default=_tenant)
    report_key = models.CharField(max_length=40, db_index=True)
    schedule = models.ForeignKey(ScheduledReport, on_delete=models.SET_NULL, null=True, blank=True, related_name="runs")
    channel = models.CharField(max_length=10, choices=CHANNELS, default="download")
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True)
    requested_by_name = models.CharField(max_length=150, blank=True)
    period_start = models.DateTimeField()
    period_end = models.DateTimeField()
    site = models.CharField(max_length=100, blank=True)
    rows = models.PositiveIntegerField(default=0)
    status = models.CharField(max_length=10, choices=STATUSES, default="ok")
    error = models.CharField(max_length=500, blank=True)
    delivered_to = models.TextField(blank=True)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.report_key} @ {self.created_at:%Y-%m-%d %H:%M}"
