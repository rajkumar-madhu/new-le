"""Periodic CMDB jobs (registered in CmdbConfig.ready, run by `manage.py run_probes`)."""
import logging

from django.conf import settings
from django.utils import timezone

from core.events import emit

from .models import ConfigurationItem, License

log = logging.getLogger("linkedeye.cmdb")

DUE_DAYS = 30          # warn this many days before a warranty / EOL / license date
STALE_DAYS = 30        # dates that passed longer ago than this are recorded silently (no event flood on first run)
MAX_EVENTS = 50        # bound per run


def ci_flag(ci):
    eol, war = ci.eol_days, ci.warranty_days
    if eol is not None and eol < 0:
        return "eol_passed", eol
    if eol is not None and eol <= DUE_DAYS:
        return "eol_due", eol
    if war is not None and war < 0:
        return "warranty_expired", war
    if war is not None and war <= DUE_DAYS:
        return "warranty_due", war
    return "", None


def license_flag(lic):
    d = lic.days_left
    if d is not None and d < 0:
        return "expired", d
    if lic.software_id and lic.over_allocated:
        return "over", None
    if d is not None and d <= DUE_DAYS:
        return "expiring", d
    return "", None


CI_TEXT = {
    "eol_passed": "reached end of life on {date}", "eol_due": "reaches end of life on {date} ({days} days)",
    "warranty_expired": "warranty expired on {date}", "warranty_due": "warranty ends on {date} ({days} days)",
}


def lifecycle_scan():
    """Emit one event per lifecycle transition of CIs and licenses. Idempotent; never raises."""
    try:
        return _scan()
    except Exception:  # noqa: BLE001 - jobs must not raise
        log.exception("cmdb lifecycle scan failed")
        return "error"


def _scan():
    tenant = settings.LINKEDEYE_TENANT
    emitted = changed = 0
    qs = (ConfigurationItem.objects.filter(tenant_key=tenant).exclude(status="retired")
          .exclude(warranty_end__isnull=True, eol_date__isnull=True, lifecycle_flag=""))
    for ci in qs.iterator():
        flag, days = ci_flag(ci)
        if flag == ci.lifecycle_flag:
            continue
        previous = ci.lifecycle_flag
        ci.lifecycle_flag = flag
        ConfigurationItem.objects.filter(pk=ci.pk).update(lifecycle_flag=flag)
        changed += 1
        if emitted >= MAX_EVENTS or (days is not None and days < -STALE_DAYS):
            continue
        if flag:
            date = ci.eol_date if flag.startswith("eol") else ci.warranty_end
            text = CI_TEXT[flag].format(date=date.isoformat(), days=days)
            emit("cmdb", f"{ci.name} {text}", severity="warning", kind="lifecycle", site=ci.site, obj=ci,
                 fingerprint=f"cmdb:lifecycle:{ci.pk}", ci=ci.name, flag=flag, previous=previous)
        else:
            emit("cmdb", f"{ci.name} lifecycle dates renewed", severity="ok", kind="lifecycle", site=ci.site, obj=ci,
                 fingerprint=f"cmdb:lifecycle:{ci.pk}", ci=ci.name, previous=previous)
        emitted += 1

    for lic in License.objects.filter(tenant_key=tenant).select_related("software"):
        flag, days = license_flag(lic)
        if flag == lic.alert_flag:
            continue
        previous = lic.alert_flag
        License.objects.filter(pk=lic.pk).update(alert_flag=flag)
        changed += 1
        if emitted >= MAX_EVENTS or (days is not None and days < -STALE_DAYS):
            continue
        if flag == "expired":
            title = f"License {lic.product} expired on {lic.expiry.isoformat()}"
        elif flag == "expiring":
            title = f"License {lic.product} expires on {lic.expiry.isoformat()} ({days} days)"
        elif flag == "over":
            title = f"License {lic.product} over-allocated: {lic.used} installs for {lic.seats} seats"
        else:
            title = f"License {lic.product} back within terms"
        emit("cmdb", title, severity="warning" if flag else "ok", kind="license", obj=lic,
             fingerprint=f"cmdb:license:{lic.pk}", flag=flag, previous=previous, seats=lic.seats, used=lic.used)
        emitted += 1
    return f"{changed} lifecycle change(s), {emitted} event(s) at {timezone.now():%H:%M}"
