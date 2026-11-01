"""Report definitions. Every report reads real records from one module and yields CSV rows.

A report whose module is not installed (or not migrated) is listed as unavailable instead of failing.
Rows are always limited to the sites the requesting user can see, and optionally to one site.
"""
import csv
import io
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Callable

from django.apps import apps
from django.conf import settings
from django.db import DatabaseError
from django.db.models import Avg, Count, Max, Q
from django.utils import timezone

from core.access import can, scope_by_site, visible_sites

MAX_ROWS = 50_000


@dataclass
class Ctx:
    start: object                # aware datetime
    end: object                  # aware datetime
    user: object = None          # rows limited to this user's sites (None = no limit, used by tests/admin tasks)
    site: str = ""               # optional single-site filter

    def scope(self, qs, field_name="site"):
        if self.user is not None:
            qs = scope_by_site(qs, self.user, field=field_name)
        if self.site:
            qs = qs.filter(**{field_name: self.site})
        return qs


@dataclass
class Report:
    key: str
    title: str
    category: str
    description: str
    app_label: str
    columns: list
    rows: Callable
    uses_period: bool = True
    perm: str = "view"
    all_sites: bool = False      # rows cannot be site-scoped: only users who see every site may run it
    icon: str = "file"
    model: str = ""              # model the report reads; missing → "not connected"
    extra: dict = field(default_factory=dict)

    def available(self):
        """Installed and providing the model it reads (a module may exist as an empty stub)."""
        if not apps.is_installed(self.app_label):
            return False
        if not self.model:
            return True
        try:
            apps.get_model(self.app_label, self.model)
            return True
        except LookupError:
            return False

    def allowed(self, user):
        if not can(user, self.perm):
            return False
        return not self.all_sites or visible_sites(user) is None


class Unavailable(Exception):
    """The module a report reads from is missing or does not have the expected model."""


def _model(app_label, name):
    try:
        return apps.get_model(app_label, name)
    except LookupError:
        raise Unavailable(f"The {app_label} module does not provide {name} yet.")


def _dt(v):
    return timezone.localtime(v).strftime("%Y-%m-%d %H:%M") if v else ""


def _minutes(a, b):
    return round((b - a).total_seconds() / 60, 1) if a and b else ""


def _pct(n, d):
    return round(100.0 * n / d, 2) if d else ""


def _p95(values):
    values = sorted(v for v in values if v is not None)
    if not values:
        return ""
    return round(values[min(len(values) - 1, int(round(0.95 * (len(values) - 1))))], 1)


# ------------------------------------------------------------------ Service Desk
def _tickets(ctx, kinds=("incident",)):
    Ticket = _model("servicedesk", "Ticket")
    qs = Ticket.objects.filter(tenant_key=settings.LINKEDEYE_TENANT, kind__in=kinds,
                               opened_at__gte=ctx.start, opened_at__lt=ctx.end)
    return ctx.scope(qs).select_related("assignee").order_by("opened_at")


def incident_rows(ctx):
    for t in _tickets(ctx).iterator():
        yield [t.number, t.title, t.priority, t.get_status_display(), t.site, t.ci_name, t.category,
               t.assignee.get_username() if t.assignee else "", t.get_source_display(), t.origin,
               _dt(t.opened_at), _dt(t.acknowledged_at), _dt(t.resolved_at),
               _minutes(t.opened_at, t.acknowledged_at), _minutes(t.opened_at, t.resolved_at),
               "yes" if t.response_breached else "no", "yes" if t.resolution_breached else "no"]


def ticket_rows(ctx):
    for t in _tickets(ctx, kinds=("incident", "problem", "change", "request")).iterator():
        yield [t.number, t.get_kind_display(), t.title, t.priority, t.get_status_display(), t.site,
               t.assignee.get_username() if t.assignee else "", _dt(t.opened_at), _dt(t.resolved_at),
               _dt(t.closed_at)]


def sla_rows(ctx):
    qs = _tickets(ctx, kinds=("incident", "request"))
    for p in ("P1", "P2", "P3", "P4"):
        sub = qs.filter(priority=p)
        agg = sub.aggregate(total=Count("id"),
                            resp_breach=Count("id", filter=Q(response_breached=True)),
                            res_breach=Count("id", filter=Q(resolution_breached=True)),
                            resolved=Count("id", filter=Q(resolved_at__isnull=False)))
        mtta = [_minutes(a, b) for a, b in sub.filter(acknowledged_at__isnull=False).values_list("opened_at", "acknowledged_at")]
        mttr = [_minutes(a, b) for a, b in sub.filter(resolved_at__isnull=False).values_list("opened_at", "resolved_at")]
        total = agg["total"]
        yield [p, total, agg["resolved"],
               _pct(total - agg["resp_breach"], total), _pct(total - agg["res_breach"], total),
               agg["resp_breach"], agg["res_breach"],
               round(sum(mtta) / len(mtta), 1) if mtta else "", round(sum(mttr) / len(mttr), 1) if mttr else ""]


# ------------------------------------------------------------------ Monitoring
def url_availability_rows(ctx):
    UrlCheck, UrlResult = _model("urlchecker", "UrlCheck"), _model("urlchecker", "UrlResult")
    checks = ctx.scope(UrlCheck.objects.filter(tenant_key=settings.LINKEDEYE_TENANT)).order_by("name")
    stats = {r["url_check_id"]: r for r in UrlResult.objects.filter(
        url_check__in=checks, checked_at__gte=ctx.start, checked_at__lt=ctx.end).values("url_check_id").annotate(
        total=Count("id"), down=Count("id", filter=Q(status="down")),
        degraded=Count("id", filter=Q(status="degraded")), avg=Avg("response_ms"), mx=Max("response_ms"))}
    for c in checks:
        s = stats.get(c.pk) or {"total": 0, "down": 0, "degraded": 0, "avg": None, "mx": None}
        times = UrlResult.objects.filter(url_check=c, checked_at__gte=ctx.start, checked_at__lt=ctx.end) \
            .values_list("response_ms", flat=True)[:20000] if s["total"] else []
        yield [c.name, c.url, c.site, c.get_check_type_display(), s["total"],
               _pct(s["total"] - s["down"], s["total"]), s["down"], s["degraded"],
               round(s["avg"], 1) if s["avg"] is not None else "", _p95(times),
               round(s["mx"], 1) if s["mx"] is not None else "", c.get_last_status_display(), _dt(c.last_checked_at)]


def domain_availability_rows(ctx):
    Domain, DomainCheck = _model("domainmonitor", "Domain"), _model("domainmonitor", "DomainCheck")
    domains = ctx.scope(Domain.objects.filter(tenant_key=settings.LINKEDEYE_TENANT), "site_key").order_by("hostname")
    stats = {r["domain_id"]: r for r in DomainCheck.objects.filter(
        domain__in=domains, checked_at__gte=ctx.start, checked_at__lt=ctx.end).values("domain_id").annotate(
        total=Count("id"), up=Count("id", filter=Q(up=True)), avg=Avg("response_ms"), mx=Max("response_ms"))}
    for d in domains:
        s = stats.get(d.pk) or {"total": 0, "up": 0, "avg": None, "mx": None}
        yield [d.hostname, d.domain_type, d.site_key, s["total"], _pct(s["up"], s["total"]), s["total"] - s["up"],
               round(s["avg"], 1) if s["avg"] is not None else "", round(s["mx"], 1) if s["mx"] is not None else "",
               d.dns_status, d.ssl_status, _dt(d.ssl_expires_at)]


def ssl_expiry_rows(ctx):
    """Certificates that expire within `ctx.end - ctx.start` from now (default 60 days), soonest first."""
    Domain = _model("domainmonitor", "Domain")
    now = timezone.now()
    horizon = now + (ctx.end - ctx.start)
    qs = ctx.scope(Domain.objects.filter(tenant_key=settings.LINKEDEYE_TENANT, is_active=True,
                                         ssl_expires_at__isnull=False, ssl_expires_at__lte=horizon), "site_key")
    for d in qs.order_by("ssl_expires_at"):
        yield [d.hostname, d.site_key, d.domain_type, d.ssl_status, _dt(d.ssl_expires_at),
               (d.ssl_expires_at - now).days]


def tcp_rows(ctx):
    TcpCheck = _model("tcpcheck", "TcpCheck")
    qs = ctx.scope(TcpCheck.objects.all()).order_by("name")
    if hasattr(TcpCheck, "tenant_key"):
        qs = qs.filter(tenant_key=settings.LINKEDEYE_TENANT)
    for c in qs:
        status = c.get_last_status_display() if hasattr(c, "get_last_status_display") else c.last_status
        yield [c.name, c.host, c.port, c.site, status, getattr(c, "last_response_ms", "") or "",
               _dt(getattr(c, "last_checked_at", None)), getattr(c, "last_error", "")]


# ------------------------------------------------------------------ Inventory
def ci_rows(ctx):
    CI = _model("cmdb", "ConfigurationItem")
    qs = ctx.scope(CI.objects.filter(tenant_key=settings.LINKEDEYE_TENANT)).order_by("ci_type", "name")
    for c in qs.iterator():
        yield [c.name, c.get_ci_type_display(), c.get_status_display(), c.get_environment_display(), c.site,
               c.owner, c.business_domain, c.ip_address or "", c.vendor, c.model, c.serial, c.asset_tag,
               c.warranty_end or "", c.eol_date or ""]


def device_rows(ctx):
    Device = _model("network", "Device")
    qs = ctx.scope(Device.objects.filter(tenant_key=settings.LINKEDEYE_TENANT)).order_by("device_type", "name")
    for d in qs.iterator():
        yield [d.name, d.get_device_type_display(), d.vendor, d.model, d.firmware, d.mgmt_ip, d.site,
               d.get_status_display(), _dt(d.last_seen), d.last_latency_ms if d.last_latency_ms is not None else ""]


# ------------------------------------------------------------------ Platform
def event_rows(ctx):
    Event = _model("core", "Event")
    qs = ctx.scope(Event.objects.filter(tenant_key=settings.LINKEDEYE_TENANT,
                                        occurred_at__gte=ctx.start, occurred_at__lt=ctx.end))
    for e in qs.order_by("occurred_at").iterator():
        yield [_dt(e.occurred_at), e.severity, e.source, e.kind, e.title, e.site, e.object_type, e.object_id,
               e.fingerprint, e.message[:500]]


def audit_rows(ctx):
    AuditEvent = _model("core", "AuditEvent")
    qs = AuditEvent.objects.filter(occurred_at__gte=ctx.start, occurred_at__lt=ctx.end)
    for a in qs.order_by("occurred_at").iterator():
        yield [_dt(a.occurred_at), a.actor_name, a.action, a.object_type, a.object_id, a.object_repr, a.result,
               a.source_ip or ""]


REPORTS = {r.key: r for r in [
    Report("incidents", "Incident register", "Service Desk",
           "Every incident opened in the period with priority, status, CI, response and resolution times and SLA breaches.",
           "servicedesk", ["Number", "Title", "Priority", "Status", "Site", "CI", "Category", "Assignee", "Source",
                           "Origin", "Opened", "Acknowledged", "Resolved", "Time to acknowledge (min)",
                           "Time to resolve (min)", "Response SLA breached", "Resolution SLA breached"],
           incident_rows, icon="alert"),
    Report("tickets", "All tickets", "Service Desk",
           "Incidents, problems, changes and service requests opened in the period.",
           "servicedesk", ["Number", "Type", "Title", "Priority", "Status", "Site", "Assignee", "Opened",
                           "Resolved", "Closed"], ticket_rows, icon="headset"),
    Report("sla", "SLA compliance by priority", "Service Desk",
           "Response and resolution SLA compliance, breaches, mean time to acknowledge and to resolve, per priority.",
           "servicedesk", ["Priority", "Tickets", "Resolved", "Response SLA met %", "Resolution SLA met %",
                           "Response breaches", "Resolution breaches", "MTTA (min)", "MTTR (min)"],
           sla_rows, icon="clock"),
    Report("url_availability", "URL availability", "Monitoring",
           "Per URL check: samples, availability, failures, average / p95 / max response time in the period.",
           "urlchecker", ["Name", "URL", "Site", "Type", "Samples", "Availability %", "Down samples",
                          "Degraded samples", "Avg response (ms)", "p95 response (ms)", "Max response (ms)",
                          "Current status", "Last checked"], url_availability_rows, icon="globe"),
    Report("domain_availability", "Domain availability", "Monitoring",
           "Per domain: checks, availability, failures, response time, DNS and SSL state in the period.",
           "domainmonitor", ["Hostname", "Type", "Site", "Checks", "Availability %", "Failed checks",
                             "Avg response (ms)", "Max response (ms)", "DNS", "SSL", "SSL expires"],
           domain_availability_rows, icon="browser"),
    Report("ssl_expiry", "SSL certificate expiry", "Monitoring",
           "Active domains whose certificate expires within the chosen number of days from today.",
           "domainmonitor", ["Hostname", "Site", "Type", "SSL status", "Expires", "Days left"],
           ssl_expiry_rows, uses_period=False, icon="lock", extra={"horizon_label": "Expiring within (days)"}),
    Report("tcp_checks", "Telnet / TCP checks", "Monitoring",
           "Current state of every TCP reachability check.",
           "tcpcheck", ["Name", "Host", "Port", "Site", "Status", "Last response (ms)", "Last checked", "Last error"],
           tcp_rows, uses_period=False, icon="plug"),
    Report("configuration_items", "Configuration items", "Inventory",
           "CMDB inventory with type, status, environment, ownership, hardware and lifecycle dates.",
           "cmdb", ["Name", "Type", "Status", "Environment", "Site", "Owner", "Business domain", "IP address",
                    "Vendor", "Model", "Serial", "Asset tag", "Warranty end", "End of life"],
           ci_rows, uses_period=False, icon="database"),
    Report("network_devices", "Network devices", "Inventory",
           "Every network device with type, vendor, firmware, management address and current state.",
           "network", ["Name", "Type", "Vendor", "Model", "Firmware", "Management IP", "Site", "Status",
                       "Last seen", "Latency (ms)"], device_rows, uses_period=False, icon="network"),
    Report("events", "Event log", "Platform",
           "Every state change, alert and log event recorded in the period.",
           "core", ["Time", "Severity", "Source", "Kind", "Title", "Site", "Object type", "Object id",
                    "Fingerprint", "Message"], event_rows, icon="list"),
    Report("audit", "Audit trail", "Platform",
           "Who changed what and when (administrators with access to every site).",
           "core", ["Time", "User", "Action", "Object type", "Object id", "Object", "Result", "Source IP"],
           audit_rows, perm="admin", all_sites=True, icon="shield"),
]}

for _key, _model_name in {"incidents": "Ticket", "tickets": "Ticket", "sla": "Ticket",
                          "url_availability": "UrlCheck", "domain_availability": "Domain", "ssl_expiry": "Domain",
                          "tcp_checks": "TcpCheck", "configuration_items": "ConfigurationItem",
                          "network_devices": "Device", "events": "Event", "audit": "AuditEvent"}.items():
    REPORTS[_key].model = _model_name

CATEGORIES = ["Service Desk", "Monitoring", "Inventory", "Platform"]


def period(days, now=None):
    now = now or timezone.now()
    return now - timedelta(days=days), now


def csv_safe(value):
    """Neutralise spreadsheet formulas (CSV injection): prefix risky leading characters with a quote."""
    if value is None:
        return ""
    s = str(value)
    if s and s[0] in "=+-@\t\r" and not _is_number(s):
        return "'" + s
    return s


def _is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        return False


def generate(report, ctx, limit=MAX_ROWS):
    """Return (rows, error). Rows are lists of display values, at most `limit`."""
    if not report.available():
        return [], f"The {report.app_label} module is not installed or not built yet."
    rows = []
    try:
        for row in report.rows(ctx):
            rows.append(row)
            if len(rows) >= limit:
                break
    except Unavailable as e:
        return [], str(e)
    except DatabaseError as e:
        return [], f"The {report.app_label} data is not available ({type(e).__name__}); run migrations."
    return rows, ""


def to_csv(report, rows):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(report.columns)
    for r in rows:
        w.writerow([csv_safe(v) for v in r])
    return buf.getvalue()
