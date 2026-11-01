"""Scheduled report delivery, run by `manage.py run_probes` every 5 minutes (job `reports.scheduled`)."""
import logging

from django.conf import settings
from django.core.mail import EmailMessage
from django.utils import timezone

from core.events import emit

from . import registry
from .models import ReportRun, ScheduledReport

log = logging.getLogger("linkedeye.reports")
BATCH = 20


def deliver(schedule, now=None, requested_by=None):
    """Generate the schedule's report and e-mail it. Records a ReportRun; never raises."""
    now = now or timezone.now()
    report = registry.REPORTS.get(schedule.report_key)
    start, end = registry.period(schedule.window_days, now)
    run = ReportRun(report_key=schedule.report_key, schedule=schedule, channel="email", period_start=start,
                    period_end=end, site=schedule.site,
                    requested_by=requested_by, requested_by_name=requested_by.get_username() if requested_by else "scheduler")
    recipients = schedule.recipient_list()
    try:
        if report is None:
            raise ValueError("Unknown report")
        owner = schedule.owner
        if owner is None or not owner.is_active:
            raise ValueError("The schedule owner is missing or inactive; assign an active owner.")
        if not report.allowed(owner):
            raise ValueError(f"The owner {owner.get_username()} may not run this report.")
        rows, error = registry.generate(report, registry.Ctx(start, end, owner, schedule.site))
        if error:
            raise ValueError(error)
        run.rows = len(rows)
        body = (f"{report.title}\n"
                f"Period: {timezone.localtime(start):%d %b %Y %H:%M} – {timezone.localtime(end):%d %b %Y %H:%M}\n"
                f"Site: {schedule.site or 'All sites visible to ' + owner.get_username()}\n"
                f"Rows: {len(rows)}\n\nSent by LinkedEye ({schedule.name}).")
        msg = EmailMessage(f"[LinkedEye] {schedule.name}", body, settings.DEFAULT_FROM_EMAIL, recipients)
        msg.attach(f"{report.key}-{timezone.localdate(now):%Y%m%d}.csv", registry.to_csv(report, rows), "text/csv")
        msg.send(fail_silently=False)
        run.status = "ok" if rows else "empty"
        run.delivered_to = ", ".join(recipients)
    except Exception as e:  # SMTP, data and configuration errors all end up on the run record
        log.warning("scheduled report %s failed: %s", schedule.pk, e)
        run.status = "failed"
        run.error = f"{type(e).__name__}: {e}"[:500]
    run.save()
    schedule.last_run_at = now
    schedule.last_status = run.status
    schedule.last_error = run.error
    schedule.next_run_at = schedule.compute_next_run(now) if schedule.enabled else None
    ScheduledReport.objects.filter(pk=schedule.pk).update(
        last_run_at=schedule.last_run_at, last_status=schedule.last_status, last_error=schedule.last_error,
        next_run_at=schedule.next_run_at)
    if run.status == "failed":
        emit("reports", f"Scheduled report “{schedule.name}” failed", severity="warning", message=run.error,
             kind="job", site=schedule.site, obj=schedule, fingerprint=f"reports:schedule:{schedule.pk}")
    return run


def run_due_schedules(now=None):
    now = now or timezone.now()
    due = ScheduledReport.objects.filter(tenant_key=settings.LINKEDEYE_TENANT, enabled=True,
                                         next_run_at__lte=now).select_related("owner").order_by("next_run_at")[:BATCH]
    sent = failed = 0
    for s in due:
        run = deliver(s, now)
        failed += run.status == "failed"
        sent += run.status != "failed"
    return f"{sent} sent, {failed} failed" if sent or failed else None
