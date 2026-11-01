"""Create clearly-marked example service desk data for demos.

* Tickets: incidents spread over the last 15 days plus a few problems, changes and service requests.
  Every example ticket's description starts with "[Example]" and its fingerprint with "example:".
* Catalog items whose description starts with "Example:".
* Example agents named example.<name> (unusable passwords, so nobody can sign in as them).

Idempotent: running it again creates nothing new. `--remove` deletes the examples again.
Never runs automatically.
"""
import random
from datetime import datetime, time, timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from servicedesk import workflow as wf
from servicedesk.models import CatalogItem, Ticket, TicketCI, TimelineEntry

TAG = "[Example] "
FP = "example:"

AGENTS = [("arul", "Arul", "Raj"), ("priya", "Priya", "Nair"), ("karthik", "Karthik", "Iyer"),
          ("divya", "Divya", "Menon"), ("ravi", "Ravi", "Shankar"), ("mani", "Mani", "Kannan")]
CLIENTS = ["WeCrew", "Finspot", "Mirae", "Client A", "Client B"]

# title, category, ci
INCIDENTS = [
    ("VPN connection issue for branch users", "Network", "fg-01"),
    ("Server CPU high on app-prod-03", "Server", "app-prod-03"),
    ("Email not delivered to external domains", "Email", "mail-relay-01"),
    ("Client portal returning HTTP 502", "Application", "portal-web-01"),
    ("Switch port flapping on core-sw-02 Gi1/0/24", "Network", "core-sw-02"),
    ("Database queries slow during BOD", "Database", "db-prod-01"),
    ("Domain trade.example.com not resolving", "DNS", "ns1"),
    ("Printer on floor 3 offline", "Hardware", "prn-f3-01"),
    ("New joiner cannot access shared drive", "Access Management", "fs-01"),
    ("Nightly backup job failed", "Server", "backup-01"),
    ("Disk space low on log server", "Server", "log-01"),
    ("SSL certificate expiring on client portal", "Security", "portal-web-01"),
    ("Packet loss on MPLS link to DR", "Network", "rtr-dr-01"),
    ("Login failures on trading terminal", "Application", "oms-01"),
    ("Market data feed delayed", "Application", "mdf-01"),
    ("Memory leak in order service", "Application", "oms-01"),
    ("DNS lookups slow from office LAN", "DNS", "ns2"),
    ("Wi-Fi outage in meeting rooms", "Network", "wlc-01"),
    ("Outlook crashes on launch", "Software", ""),
    ("File server share unreachable", "Server", "fs-01"),
]
PRIORITY_WEIGHTS = [("P1", 1), ("P2", 3), ("P3", 6), ("P4", 4)]
COMMENTS = [
    "Checked monitoring: the alert started right after the scheduled job.", "Restarted the service; watching for recurrence.",
    "Vendor ticket raised, waiting for an update.", "User confirmed the issue is fixed.",
    "Collected logs and attached them to the vendor case.", "Workaround applied: traffic moved to the secondary link.",
]
CATALOG = [
    ("New user account", "Accounts", "Create a domain account, mailbox and default group memberships for a new joiner.", 24, "P3"),
    ("VPN access", "Access", "Grant remote VPN access (requires manager approval in the details).", 8, "P3"),
    ("Password reset", "Accounts", "Reset a forgotten password or unlock an account.", 2, "P2"),
    ("Laptop replacement", "Hardware", "Replace a faulty or end-of-life laptop; data migration included.", 72, "P4"),
    ("Software installation", "Software", "Install licensed software from the approved list.", 24, "P4"),
    ("Shared mailbox", "Accounts", "Create a shared mailbox and grant access to listed users.", 24, "P4"),
    ("Firewall rule request", "Network", "Open a port or allow a flow; include source, destination, port and business reason.", 48, "P3"),
    ("New virtual machine", "Hardware", "Provision a VM from the standard template (CPU, RAM, disk in the details).", 48, "P3"),
]


def _user(username, first, last):
    User = get_user_model()
    u, created = User.objects.get_or_create(username=f"example.{username}", defaults={
        "first_name": first, "last_name": last, "is_staff": True, "email": f"{username}@example.com"})
    if created:
        u.set_unusable_password()
        u.save(update_fields=["password"])
    return u


class Command(BaseCommand):
    help = "Create example service desk tickets, catalog items and agents (all clearly marked as examples)."

    def add_arguments(self, parser):
        parser.add_argument("--remove", action="store_true", help="Delete the example tickets, catalog items and agents.")

    def handle(self, *args, **opts):
        tenant = settings.LINKEDEYE_TENANT
        if opts["remove"]:
            n = Ticket.objects.filter(tenant_key=tenant, fingerprint__startswith=FP).delete()[1].get("servicedesk.Ticket", 0)
            c = CatalogItem.objects.filter(tenant_key=tenant, description__startswith="Example:").delete()[0]
            User = get_user_model()
            u = User.objects.filter(username__in=[f"example.{a[0]}" for a in AGENTS]).delete()[1].get(User._meta.label, 0)
            self.stdout.write(self.style.SUCCESS(f"Removed {n} example tickets, {c} catalog items and {u} example agents."))
            return
        with transaction.atomic():
            created = self._seed(tenant)
        self.stdout.write(self.style.SUCCESS(created))

    # ------------------------------------------------------------------
    def _seed(self, tenant):
        rng = random.Random(1287)
        now = timezone.now()
        agents = [_user(*a) for a in AGENTS]
        items = {}
        new_items = 0
        for name, cat, desc, hours, prio in CATALOG:
            obj, made = CatalogItem.objects.get_or_create(tenant_key=tenant, name=name, defaults={
                "category": cat, "description": f"Example: {desc}", "fulfilment_hours": hours, "default_priority": prio})
            items[name] = obj
            new_items += made
        if Ticket.objects.filter(tenant_key=tenant, fingerprint__startswith=FP).exists():
            return f"Example tickets already exist; {new_items} catalog item(s) added. Use --remove to start over."

        from core.models import Site
        sites = list(Site.objects.filter(tenant_key=tenant).values_list("name", flat=True)[:4]) or [""]

        specs = []
        # 46 incidents over the last 15 days (more on recent days) + 24 older, closed ones (days 15-30) so the
        # overview's "vs previous period" deltas have something to compare with.
        forced = {0: (0.08, "P1", "investigating"), 1: (0.45, "P1", "acknowledged"), 2: (1.2, "P2", "new"),
                  3: (2.5, "P3", "investigating"), 4: (4.2, "P2", "mitigated")}
        for i in range(70):
            title, cat, ci = INCIDENTS[(i * 7) % len(INCIDENTS)]
            if i in forced:
                days_ago, prio, state = forced[i]
            else:
                days_ago = rng.random() ** 1.3 * 15 if i < 46 else 15 + rng.random() * 15
                prio = rng.choices([p for p, _ in PRIORITY_WEIGHTS], [w for _, w in PRIORITY_WEIGHTS])[0]
                state = "closed" if i >= 46 else ""
            opened = now - timedelta(days=days_ago, minutes=rng.randint(0, 50))
            specs.append(("incident", f"inc{i}", title, cat, ci, opened, prio, state))
        problems = [("prb0", "Recurring VPN drops for branch users", "Network", "fg-01", 9, "P2", "investigating"),
                    ("prb1", "Slow database queries during BOD", "Database", "db-prod-01", 12, "P2", "known_error"),
                    ("prb2", "Port flapping on core-sw-02", "Network", "core-sw-02", 14, "P3", "resolved"),
                    ("prb3", "Intermittent DNS timeouts from office LAN", "DNS", "ns2", 2, "P3", "new")]
        for key, title, cat, ci, ago, prio, status in problems:
            specs.append(("problem", key, title, cat, ci, now - timedelta(days=ago, hours=3), prio, status))
        changes = [("chg0", "Upgrade FG-01 firmware to 7.2.8", "Network", "fg-01", 4, "P2", "scheduled", "high", 1, 22, 90),
                   ("chg1", "Add 500 GB to db-prod-01 data volume", "Database", "db-prod-01", 1, "P3", "submitted", "medium", 3, 21, 60),
                   ("chg2", "Rotate TLS certificates on client portal", "Security", "portal-web-01", 10, "P3", "closed", "low", -7, 20, 30),
                   ("chg3", "Increase VPN licence pool to 500 users", "Network", "fg-01", 3, "P3", "approved", "low", 4, 19, 45),
                   ("chg4", "Decommission legacy mail relay", "Email", "mail-relay-01", 8, "P4", "rejected", "high", None, 0, 0),
                   ("chg5", "Patch Windows servers (monthly)", "Server", "", 0, "P3", "draft", "medium", None, 0, 0)]
        for c in changes:
            specs.append(("change",) + c)
        requests = [("req0", "New user account", 6, "fulfilled"), ("req1", "VPN access", 2, "in_progress"),
                    ("req2", "Laptop replacement", 5, "new"), ("req3", "Password reset", 0.1, "new"),
                    ("req4", "Software installation", 9, "closed"), ("req5", "Firewall rule request", 1, "in_progress")]
        for key, item, ago, status in requests:
            specs.append(("request", key, item, ago, status))

        def when(s):
            if s[0] in ("incident", "problem"):
                return s[5]
            if s[0] == "change":
                return now - timedelta(days=s[5], hours=5)
            return now - timedelta(days=s[3])
        specs.sort(key=when)

        made = {}
        for s in specs:
            t = getattr(self, f"_{s[0]}")(s, rng, now, agents, items, tenant, sites, when(s))
            made[s[1]] = t
        # link incidents to problems
        for key, t in made.items():
            if t.kind != "incident":
                continue
            target = {"fg-01": "prb0", "db-prod-01": "prb1", "core-sw-02": "prb2", "ns2": "prb3"}.get(t.ci_name)
            if target and rng.random() < 0.7 and made[target].opened_at < t.opened_at + timedelta(days=3):
                t.problem = made[target]
                t.save(update_fields=["problem"])
                self._note(made[target], "link", f"Incident {t.number} linked.", made[target].assignee, max(t.opened_at, made[target].opened_at) + timedelta(hours=1), new=t.number)
        n = len(made)
        return (f"Created {n} example tickets ({sum(1 for t in made.values() if t.kind == 'incident')} incidents), "
                f"{new_items} catalog item(s) and {len(agents)} example agents.")

    # ------------------------------------------------------------------ builders
    def _note(self, t, kind, body, user=None, at=None, old="", new="", name=""):
        at = min(at or timezone.now(), timezone.now())
        return TimelineEntry.objects.create(ticket=t, kind=kind, body=body, author=user, created_at=at,
                                            author_name=(user.get_full_name() if user else "") or name or "system",
                                            old_value=old, new_value=new)

    def _base(self, kind, title, opened, prio, tenant, **kw):
        t = Ticket(tenant_key=tenant, kind=kind, title=title[:200], priority=prio, opened_at=opened,
                   status=wf.INITIAL[kind], reporter_name=kw.pop("reporter_name", "Example data"), **kw)
        t.save()
        self._note(t, "system", f"{t.get_kind_display()} opened{' from an alert' if t.source == 'alert' else ''}.",
                   at=opened, new=t.status, name=t.reporter_name)
        return t

    def _walk(self, t, path, times, user, notes=None):
        """Apply status changes (path[i] at times[i]) with timestamps and timeline entries."""
        prev = t.status
        for i, (status, at) in enumerate(zip(path, times)):
            if at > timezone.now():
                break
            if prev == wf.INITIAL[t.kind] and t.acknowledged_at is None and status != "draft":
                t.acknowledged_at = at
            if status in wf.RESOLVING and t.resolved_at is None:
                t.resolved_at = at
            if status in wf.FINAL:
                t.closed_at = at
                t.resolved_at = t.resolved_at or at
            note = (notes or {}).get(status, "")
            self._note(t, "status", f"Status changed to {wf.STATUS_LABELS[status]}" + (f": {note}" if note else "."), user, at,
                       old=prev, new=status)
            if note and status in wf.RESOLVING:
                t.resolution = note
            prev = t.status = status
        return t

    def _flag(self, t, now):
        if t.response_due and (t.acknowledged_at or now) > t.response_due and (t.acknowledged_at or t.is_open):
            t.response_breached = True
            self._note(t, "sla", f"Response SLA breached (was due {timezone.localtime(t.response_due):%d %b %H:%M}).",
                       at=t.response_due, new="response_breached", name="SLA monitor")
        if t.resolution_due and (t.resolved_at or now) > t.resolution_due and (t.resolved_at or t.is_open):
            t.resolution_breached = True
            self._note(t, "sla", f"Resolution SLA breached (was due {timezone.localtime(t.resolution_due):%d %b %H:%M}).",
                       at=t.resolution_due, new="resolution_breached", name="SLA monitor")

    def _incident(self, s, rng, now, agents, items, tenant, sites, opened):
        _, key, title, cat, ci, opened, prio, state = s
        source = "alert" if rng.random() < 0.45 else "manual"
        t = self._base("incident", title, opened, prio, tenant, category=cat, ci_name=ci, client=rng.choice(CLIENTS),
                       site=rng.choice(sites), source=source, origin="urlchecker" if source == "alert" else "",
                       fingerprint=f"{FP}{key}", reporter_name="urlchecker" if source == "alert" else "Service desk",
                       description=TAG + f"{title}. Reported {'by monitoring' if source == 'alert' else 'by a user'}; "
                                         f"affects {ci or 'end users'}.")
        age_h = (now - opened).total_seconds() / 3600
        agent = rng.choice(agents) if (rng.random() < 0.8 or age_h > 30) and state != "new" else None
        resp = {"P1": 10, "P2": 25, "P3": 150, "P4": 300}[prio] * rng.uniform(0.3, 1.6)
        fix_h = {"P1": 3, "P2": 6, "P3": 18, "P4": 50}[prio] * rng.uniform(0.3, 1.5)
        open_paths = {"new": [], "acknowledged": ["acknowledged"], "investigating": ["acknowledged", "investigating"],
                      "mitigated": ["acknowledged", "investigating", "mitigated"]}
        if not state and (age_h < 36 and rng.random() < 0.55 or rng.random() < 0.12):
            state = rng.choice(["new", "acknowledged", "investigating", "investigating", "mitigated"])
        if state in open_paths:
            path = open_paths[state]
            fix_h = max(fix_h, age_h + 1)   # still open: the status changes happened along the way
        elif age_h > fix_h + 24 or state == "closed":
            path = ["acknowledged", "investigating", "resolved", "closed"]
        else:
            path = ["acknowledged", "investigating", "mitigated", "resolved"]
        ack = opened + timedelta(minutes=resp)
        res = opened + timedelta(hours=fix_h)
        times = [ack, ack + (res - ack) * 0.3, res - timedelta(minutes=20) if path[2:3] == ["mitigated"] else res,
                 res + timedelta(hours=rng.uniform(4, 20))]
        if len(path) == 4 and path[2] == "mitigated":
            times[3] = res
        if state in open_paths:
            ack = min(ack, now - (now - opened) * 0.6)
            times = [ack, ack + (now - ack) * 0.4, ack + (now - ack) * 0.8]
        if agent:
            t.assignee = agent
            self._note(t, "assignment", f"Assigned to {agent.get_full_name()}.", None, opened + timedelta(minutes=min(resp, 5)),
                       new=agent.get_username(), name="Service desk")
        self._walk(t, path, times, agent, notes={"resolved": "Root cause fixed and service verified."})
        if rng.random() < 0.6 and path:
            self._note(t, "comment", rng.choice(COMMENTS), agent, ack + timedelta(minutes=rng.randint(5, 90)))
        self._flag(t, now)
        t.save()
        return t

    def _problem(self, s, rng, now, agents, items, tenant, sites, opened):
        _, key, title, cat, ci, ago, prio, status = s
        t = self._base("problem", title, opened, prio, tenant, category=cat, ci_name=ci, fingerprint=f"{FP}{key}",
                       description=TAG + f"Several incidents point to a common cause on {ci or 'shared infrastructure'}.",
                       reporter_name="Problem manager")
        agent = agents[len(key) % len(agents)] if status != "new" else None
        if agent:
            t.assignee = agent
        path = {"new": [], "investigating": ["investigating"], "known_error": ["investigating", "known_error"],
                "resolved": ["investigating", "known_error", "resolved"]}[status]
        times = [opened + timedelta(hours=4 + 20 * i) for i in range(len(path))]
        if status in ("known_error", "resolved"):
            t.root_cause = "Connection pool exhausted when BOD batch and reporting run together." if ci == "db-prod-01" else \
                f"Faulty optic on {ci} causing link renegotiation."
            t.workaround = "Stagger the reporting jobs 30 minutes after BOD." if ci == "db-prod-01" else "Traffic moved to the redundant port."
        self._walk(t, path, times, agent, notes={"resolved": "Optic replaced; no flaps for 7 days."})
        t.save()
        return t

    def _change(self, s, rng, now, agents, items, tenant, sites, opened):
        _, key, title, cat, ci, ago, prio, status, risk, start_days, start_hour, minutes = s
        t = self._base("change", title, opened, prio, tenant, category=cat, ci_name=ci, risk=risk, fingerprint=f"{FP}{key}",
                       description=TAG + f"{title}.", reporter_name="Change manager",
                       implementation_plan="1. Take config backup\n2. Apply change in the window\n3. Verify service health checks",
                       backout_plan="Restore the backup taken in step 1 and re-run the health checks.")
        if start_days is not None:
            day = timezone.localdate(now) + timedelta(days=start_days)
            start = timezone.make_aware(datetime.combine(day, time.min)) + timedelta(hours=start_hour)
            t.planned_start, t.planned_end = start, start + timedelta(minutes=minutes)
        agent = agents[(int(key[-1]) + 2) % len(agents)]
        t.assignee = agent
        path = {"draft": [], "submitted": ["submitted"], "approved": ["submitted", "approved"],
                "scheduled": ["submitted", "approved", "scheduled"], "rejected": ["submitted", "rejected"],
                "closed": ["submitted", "approved", "scheduled", "implemented", "closed"]}[status]
        times = [opened + timedelta(hours=2 + 6 * i) for i in range(len(path))]
        if status == "closed" and t.planned_end:
            times[3] = min(t.planned_end, now)
            times[4] = min(t.planned_end + timedelta(hours=12), now)
        self._walk(t, path, times, agent)
        if "approved" in path:
            t.approved_by = agents[0] if agent != agents[0] else agents[1]
            t.approved_at = times[path.index("approved")]
            # the approval on the timeline is the approver's, not the change owner's
            t.timeline.filter(kind="status", new_value="approved").update(
                author=t.approved_by, author_name=t.approved_by.get_full_name() or t.approved_by.get_username())
        t.save()
        if ci:
            TicketCI.objects.get_or_create(ticket=t, ci_name=ci, defaults={"note": "primary"})
        return t

    def _request(self, s, rng, now, agents, items, tenant, sites, opened):
        _, key, item_name, ago, status = s
        item = items[item_name]
        t = self._base("request", f"Request: {item.name}", opened, item.default_priority, tenant, category=item.category,
                       catalog_item=item, source="catalog", client=rng.choice(CLIENTS), fingerprint=f"{FP}{key}",
                       description=TAG + "Requested through the service catalog.", reporter_name="Service catalog")
        agent = rng.choice(agents) if status != "new" else None
        t.assignee = agent
        path = {"new": [], "in_progress": ["in_progress"], "fulfilled": ["in_progress", "fulfilled"],
                "closed": ["in_progress", "fulfilled", "closed"]}[status]
        times = [opened + timedelta(hours=1 + 0.4 * item.fulfilment_hours * i) for i in range(len(path))]
        self._walk(t, path, times, agent, notes={"fulfilled": "Done and confirmed with the requester."})
        self._flag(t, now)
        t.save()
        return t
