import csv
import io
from datetime import timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.core.management import call_command
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from core import jobs
from core.events import emit
from core.models import AuditEvent, Event, Membership, Site

from . import services, sla, stats
from . import workflow as wf
from .models import CatalogItem, SlaPolicy, Ticket, TicketCI, TimelineEntry
from .signals import fingerprint_for


@override_settings(NOTIFY_WEBHOOK_URLS=[], NOTIFY_EMAILS=[], INCIDENT_AUTO_CREATE=True)
class Base(TestCase):
    """No outbound notifications: the webhook sender is patched for every test."""

    def setUp(self):
        p = mock.patch("core.notify._post", side_effect=AssertionError("network call in tests"))
        p.start()
        self.addCleanup(p.stop)
        self.viewer = User.objects.create_user("viewer", password="x")
        self.op = User.objects.create_user("op", password="x", is_staff=True, first_name="Olivia", last_name="Op")
        self.op2 = User.objects.create_user("op2", password="x", is_staff=True)
        self.admin = User.objects.create_superuser("root", "root@example.com", "x")

    def login(self, user, csrf=False):
        c = Client(enforce_csrf_checks=csrf)
        c.force_login(user)
        return c

    def incident(self, **kw):
        kw.setdefault("title", "Website down")
        kw.setdefault("priority", "P2")
        return services.create_ticket(user=kw.pop("user", self.op), kind=kw.pop("kind", "incident"), **kw)


# ------------------------------------------------------------------ models
class ModelTests(Base):
    def test_default_sla_policies_seeded_by_migration(self):
        got = {p.priority: (p.response_minutes, p.resolution_minutes) for p in SlaPolicy.objects.all()}
        self.assertEqual(got, {"P1": (15, 240), "P2": (30, 480), "P3": (240, 1440), "P4": (480, 4320)})

    def test_numbers_are_sequential_per_kind(self):
        a = self.incident()
        b = self.incident()
        p = services.create_ticket(kind="problem", title="Root cause")
        c = services.create_ticket(kind="change", title="Upgrade")
        r = services.create_ticket(kind="request", title="Laptop")
        self.assertEqual([a.number, b.number, p.number, c.number, r.number],
                         ["INC-1001", "INC-1002", "PRB-1001", "CHG-1001", "REQ-1001"])
        self.assertEqual((p.status, c.status, r.status), ("new", "draft", "new"))

    def test_numbering_never_reuses_after_delete_and_survives_counter_loss(self):
        a = self.incident()
        a.delete()
        self.assertEqual(self.incident().number, "INC-1002")
        from .models import TicketCounter
        TicketCounter.objects.all().delete()   # counter lost: never below the highest existing number
        self.assertEqual(self.incident().number, "INC-1003")

    def test_sla_due_dates_from_policy(self):
        t = self.incident(priority="P1")
        self.assertEqual(t.response_due - t.opened_at, timedelta(minutes=15))
        self.assertEqual(t.resolution_due - t.opened_at, timedelta(minutes=240))
        chg = services.create_ticket(kind="change", title="x", priority="P1")
        self.assertIsNone(chg.response_due)
        self.assertIsNone(chg.resolution_due)

    def test_catalog_request_uses_fulfilment_hours(self):
        item = CatalogItem.objects.create(name="Laptop", fulfilment_hours=72, default_priority="P4")
        t = services.request_from_catalog(item, self.op, details="Need one")
        self.assertEqual((t.kind, t.source, t.priority, t.catalog_item), ("request", "catalog", "P4", item))
        self.assertEqual(t.resolution_due - t.opened_at, timedelta(hours=72))
        self.assertEqual(t.reporter, self.op)

    def test_open_and_done_querysets(self):
        a = self.incident()
        b = self.incident()
        services.transition(b, "resolved", self.op)
        self.assertEqual(list(Ticket.objects.open()), [a])
        self.assertEqual(list(Ticket.objects.done()), [b])


# ------------------------------------------------------------------ workflow + services
class WorkflowTests(Base):
    def test_every_transition_target_is_a_valid_status_of_its_kind(self):
        for kind, table in wf.TRANSITIONS.items():
            self.assertEqual(set(table), set(wf.FLOW[kind]))
            for src, targets in table.items():
                for target, label, style in targets:
                    self.assertIn(target, wf.FLOW[kind], (kind, src, target))

    def test_incident_lifecycle_timestamps_timeline_and_events(self):
        t = self.incident()
        services.transition(t, "acknowledged", self.op)
        self.assertIsNotNone(t.acknowledged_at)
        services.transition(t, "investigating", self.op)
        services.transition(t, "mitigated", self.op)
        services.transition(t, "resolved", self.op, note="Rebooted")
        self.assertIsNotNone(t.resolved_at)
        self.assertEqual(t.resolution, "Rebooted")
        services.transition(t, "closed", self.op)
        self.assertIsNotNone(t.closed_at)
        statuses = list(t.timeline.filter(kind="status").order_by("pk").values_list("new_value", flat=True))
        self.assertEqual(statuses, ["acknowledged", "investigating", "mitigated", "resolved", "closed"])
        self.assertTrue(Event.objects.filter(source="servicedesk", fingerprint=f"servicedesk:{t.pk}", severity="ok").exists())
        # reopen
        services.transition(t, "investigating", self.op)
        t.refresh_from_db()
        self.assertEqual(t.status, "investigating")
        self.assertIsNone(t.resolved_at)
        self.assertIsNone(t.closed_at)
        self.assertTrue(t.timeline.filter(body__startswith="Reopened").exists())

    def test_invalid_transitions_rejected(self):
        t = self.incident()
        with self.assertRaises(services.WorkflowError):
            services.transition(t, "closed", self.op)
        with self.assertRaises(services.WorkflowError):
            services.transition(t, "known_error", self.op)
        p = services.create_ticket(kind="problem", title="p")
        with self.assertRaises(services.WorkflowError):
            services.transition(p, "acknowledged", self.op)
        for target in ("investigating", "known_error", "resolved", "closed"):
            services.transition(p, target, self.op)
        self.assertEqual(p.transitions(), [])

    def test_request_flow(self):
        r = services.create_ticket(kind="request", title="r")
        for target in ("in_progress", "fulfilled", "closed"):
            services.transition(r, target, self.op)
        self.assertIsNotNone(r.resolved_at)
        self.assertEqual(r.status, "closed")

    def test_change_approval_rules(self):
        c = services.create_ticket(user=self.op, kind="change", title="Upgrade firewall")
        services.transition(c, "submitted", self.op)
        self.assertEqual(c.approval_state, "pending")
        with self.assertRaises(services.WorkflowError):   # requester cannot approve own change
            services.transition(c, "approved", self.op)
        services.transition(c, "approved", self.op2)
        self.assertEqual((c.approved_by, c.approval_state), (self.op2, "approved"))
        with self.assertRaises(services.WorkflowError):   # no window yet
            services.transition(c, "scheduled", self.op2)
        c.planned_start = timezone.now() + timedelta(days=1)
        c.planned_end = c.planned_start + timedelta(hours=1)
        c.save()
        services.transition(c, "scheduled", self.op2)
        services.transition(c, "implemented", self.op2)
        services.transition(c, "closed", self.op2)
        self.assertEqual(c.status, "closed")

    def test_change_rejection_and_admin_self_approval(self):
        c = services.create_ticket(user=self.admin, kind="change", title="x")
        services.transition(c, "submitted", self.admin)
        services.transition(c, "rejected", self.op)
        self.assertEqual((c.approval_state, c.approved_by), ("rejected", None))
        self.assertIsNotNone(c.closed_at)
        services.transition(c, "draft", self.admin)
        services.transition(c, "submitted", self.admin)
        services.transition(c, "approved", self.admin)   # admins may approve their own
        self.assertEqual(c.status, "approved")

    def test_assign_priority_comment_link_ci(self):
        t = self.incident(priority="P3")
        services.assign(t, self.op, self.admin)
        services.assign(t, self.op2, self.admin)
        services.assign(t, None, self.admin)
        bodies = list(t.timeline.filter(kind="assignment").order_by("pk").values_list("body", flat=True))
        self.assertEqual(bodies, ["Assigned to Olivia Op.", "Reassigned from Olivia Op to op2.", "Unassigned."])
        services.set_priority(t, "P1", self.op)
        self.assertEqual(t.resolution_due - t.opened_at, timedelta(minutes=240))
        with self.assertRaises(services.WorkflowError):
            services.set_priority(t, "P9", self.op)
        with self.assertRaises(services.WorkflowError):
            services.comment(t, "   ", self.op)
        services.comment(t, "Looking", self.op)
        self.assertEqual(t.timeline.filter(kind="comment").get().author, self.op)
        p = services.create_ticket(kind="problem", title="p")
        services.link_problem(t, p, self.op)
        self.assertEqual(list(p.incidents.all()), [t])
        self.assertTrue(p.timeline.filter(kind="link").exists())
        with self.assertRaises(services.WorkflowError):
            services.link_problem(p, p, self.op)
        services.link_problem(t, None, self.op)
        self.assertIsNone(Ticket.objects.get(pk=t.pk).problem)
        c = services.create_ticket(kind="change", title="c")
        services.add_ci(c, "fw-01", self.op)
        services.add_ci(c, "fw-01", self.op)   # idempotent
        self.assertEqual(c.cis.count(), 1)
        with self.assertRaises(services.WorkflowError):
            services.add_ci(c, " ", self.op)
        services.remove_ci(c.cis.get(), self.op)
        self.assertEqual(c.cis.count(), 0)


class OpenIncidentTests(Base):
    def test_open_incident_creates_and_dedupes_by_fingerprint(self):
        a = services.open_incident("DB down", "x", priority="P3", site="DR Site", source="urlchecker", fingerprint="db:1", ci_name="db-01")
        self.assertEqual((a.kind, a.source, a.origin, a.ci_name, a.site), ("incident", "alert", "urlchecker", "db-01", "DR Site"))
        b = services.open_incident("DB down again", priority="P1", source="urlchecker", fingerprint="db:1")
        self.assertEqual(a.pk, b.pk)
        self.assertEqual(Ticket.objects.count(), 1)
        b.refresh_from_db()
        self.assertEqual(b.priority, "P1")   # escalated, never downgraded
        self.assertTrue(b.timeline.filter(body__startswith="Duplicate alert").exists())
        services.open_incident("DB down", priority="P4", fingerprint="db:1")
        self.assertEqual(Ticket.objects.get().priority, "P1")

    def test_new_incident_after_previous_one_resolved(self):
        a = services.open_incident("x", fingerprint="f")
        services.transition(a, "resolved", self.op)
        b = services.open_incident("x", fingerprint="f")
        self.assertNotEqual(a.pk, b.pk)

    def test_mitigated_incident_goes_back_to_investigating_on_new_alert(self):
        a = services.open_incident("x", fingerprint="f")
        for s in ("acknowledged", "mitigated"):
            services.transition(a, s, self.op)
        services.open_incident("x", fingerprint="f")
        a.refresh_from_db()
        self.assertEqual(a.status, "investigating")

    def test_resolve_by_fingerprint(self):
        a = services.open_incident("x", fingerprint="f")
        self.assertEqual(services.resolve_by_fingerprint("f", note="cleared"), 1)
        a.refresh_from_db()
        self.assertEqual((a.status, a.resolution), ("resolved", "cleared"))
        self.assertEqual(services.resolve_by_fingerprint("f"), 0)
        self.assertEqual(services.resolve_by_fingerprint(""), 0)

    def test_invalid_priority_falls_back(self):
        self.assertEqual(services.open_incident("x", priority="urgent").priority, "P3")


# ------------------------------------------------------------------ event listener
class ListenerTests(Base):
    def test_critical_event_opens_p2_incident(self):
        emit(source="urlchecker", title="Portal down", severity="critical", message="HTTP 502", site="DR Site",
             fingerprint="urlchecker:7", host="portal-01")
        t = Ticket.objects.get()
        self.assertEqual((t.kind, t.priority, t.fingerprint, t.site, t.origin, t.ci_name),
                         ("incident", "P2", "urlchecker:7", "DR Site", "urlchecker", "portal-01"))
        self.assertIn("HTTP 502", t.description)

    def test_priority_p1_and_default_fingerprint(self):
        emit(source="network", title="Core switch down", severity="critical", priority="P1")
        t = Ticket.objects.get()
        self.assertEqual((t.priority, t.fingerprint), ("P1", "evt:Core switch down"))

    def test_duplicate_critical_events_dedupe(self):
        for _ in range(3):
            emit(source="tcpcheck", title="Port 443 closed", severity="critical", fingerprint="tcp:1")
        self.assertEqual(Ticket.objects.count(), 1)
        self.assertEqual(Ticket.objects.get().timeline.filter(body__startswith="Duplicate alert").count(), 2)

    def test_ignored_events(self):
        emit(source="servicedesk", title="x", severity="critical")
        emit(source="urlchecker", title="slow", severity="warning")
        emit(source="urlchecker", title="fyi", severity="info")
        with override_settings(INCIDENT_AUTO_CREATE=False):
            emit(source="urlchecker", title="down", severity="critical")
        self.assertEqual(Ticket.objects.count(), 0)

    def test_recovery_moves_open_incident_to_mitigated(self):
        emit(source="urlchecker", title="Portal down", severity="critical", fingerprint="u:1")
        emit(source="urlchecker", title="Portal up", severity="ok", fingerprint="u:1")
        t = Ticket.objects.get()
        self.assertEqual(t.status, "mitigated")
        self.assertTrue(t.timeline.filter(body__startswith="Recovered").exists())
        self.assertIsNotNone(t.acknowledged_at)
        # recovery with no matching incident does nothing
        emit(source="urlchecker", title="Other up", severity="ok", fingerprint="u:2")
        self.assertEqual(Ticket.objects.count(), 1)

    def test_recovery_by_title_fingerprint(self):
        emit(source="bodeod", title="BOD failed", severity="critical")
        emit(source="bodeod", title="BOD failed", severity="ok")
        self.assertEqual(Ticket.objects.get().status, "mitigated")

    def test_listener_never_raises(self):
        with mock.patch("servicedesk.services.open_incident", side_effect=RuntimeError("boom")), \
                self.assertLogs("linkedeye.servicedesk", "ERROR"):
            ev = emit(source="urlchecker", title="x", severity="critical")
        self.assertIsNotNone(ev.pk)

    def test_fingerprint_for(self):
        self.assertEqual(fingerprint_for(Event(title="t", fingerprint="")), "evt:t")
        self.assertEqual(fingerprint_for(Event(title="t", fingerprint="a:1")), "a:1")


# ------------------------------------------------------------------ SLA job
class SlaTests(Base):
    def test_job_is_registered(self):
        self.assertIn("servicedesk.sla", jobs.JOBS)
        self.assertEqual(jobs.JOBS["servicedesk.sla"]["interval"], 60)

    def test_breaches_flagged_once_with_one_warning_event_each(self):
        t = self.incident(priority="P1")
        Ticket.objects.filter(pk=t.pk).update(opened_at=timezone.now() - timedelta(hours=5),
                                              response_due=timezone.now() - timedelta(hours=4),
                                              resolution_due=timezone.now() - timedelta(hours=1))
        self.assertIn("2 SLA breach", sla.flag_breaches())
        t.refresh_from_db()
        self.assertTrue(t.response_breached and t.resolution_breached)
        events = Event.objects.filter(kind="sla_breach")
        self.assertEqual(events.count(), 2)
        self.assertEqual(set(events.values_list("severity", flat=True)), {"warning"})
        self.assertEqual(sla.flag_breaches(), "no new SLA breaches")
        self.assertEqual(Event.objects.filter(kind="sla_breach").count(), 2)
        self.assertEqual(t.timeline.filter(kind="sla").count(), 2)

    def test_resolved_in_time_is_not_breached(self):
        t = self.incident(priority="P4")
        services.transition(t, "resolved", self.op)
        self.assertEqual(sla.overall(t), "met")
        self.assertEqual(sla.flag_breaches(), "no new SLA breaches")

    def test_late_acknowledgement_flags_response(self):
        t = self.incident(priority="P1")
        Ticket.objects.filter(pk=t.pk).update(response_due=timezone.now() - timedelta(minutes=1))
        t.refresh_from_db()
        services.transition(t, "acknowledged", self.op)
        t.refresh_from_db()
        self.assertTrue(t.response_breached)
        self.assertFalse(t.resolution_breached)

    def test_sla_cell_shows_response_breach_on_closed_ticket(self):
        from .templatetags.sd import sla_cell
        t = self.incident(priority="P3")
        services.transition(t, "resolved", self.op)
        self.assertIn("tn-ok", sla_cell(t))
        Ticket.objects.filter(pk=t.pk).update(response_breached=True)
        t.refresh_from_db()
        self.assertIn("Response SLA breached", sla_cell(t))

    def test_clock_states(self):
        now = timezone.now()
        start = now - timedelta(minutes=90)
        self.assertEqual(sla.clock(now + timedelta(minutes=10), None, start, False, now)["state"], "at_risk")
        self.assertEqual(sla.clock(now + timedelta(minutes=60), None, start, False, now)["state"], "on_track")
        self.assertEqual(sla.clock(now - timedelta(minutes=1), None, start, False, now)["state"], "breached")
        self.assertEqual(sla.clock(now, now - timedelta(minutes=5), start, False, now)["state"], "met")
        self.assertEqual(sla.clock(None, None, start, False, now)["state"], "none")
        self.assertEqual(sla.fmt_minutes(1500), "1d 1h")

    def test_job_survives_errors(self):
        t = self.incident(priority="P1")
        Ticket.objects.filter(pk=t.pk).update(response_due=timezone.now() - timedelta(hours=1))
        with mock.patch("servicedesk.sla.check", side_effect=RuntimeError("x")), self.assertLogs("linkedeye.servicedesk", "ERROR"):
            self.assertEqual(sla.flag_breaches(), "no new SLA breaches")


# ------------------------------------------------------------------ overview stats
class StatsTests(Base):
    def test_overview_counts_and_deltas(self):
        now = timezone.now()
        for prio, ago in (("P1", 1), ("P2", 2), ("P2", 3), ("P3", 20)):
            t = self.incident(priority=prio)
            Ticket.objects.filter(pk=t.pk).update(opened_at=now - timedelta(days=ago))
        r = Ticket.objects.get(priority="P2", opened_at__lt=now - timedelta(days=2, hours=12))
        services.transition(r, "resolved", self.op)
        d = stats.overview(Ticket.objects.filter(kind="incident"), 15)
        k = {x["key"]: x for x in d["kpis"]}
        self.assertEqual((k[""]["value"], k[""]["prev"], k[""]["delta"]), (3, 1, 200))
        self.assertEqual((k["P1"]["value"], k["P2"]["value"], k["P3"]["value"], k["P3"]["prev"], k["P3"]["delta"]), (1, 2, 0, 1, -100))
        self.assertEqual(k[""]["sub"], "2 open, 1 resolved")
        self.assertEqual(sum(d["trend"]["series"][0]["values"]), 3)
        self.assertEqual(sum(d["trend"]["series"][1]["values"]), 1)
        self.assertEqual(sum(s["value"] for s in d["status_segments"]), 3)
        self.assertEqual(d["categories"][0]["name"], "Uncategorised")
        self.assertEqual(len(d["trend"]["labels"]), 15)
        self.assertEqual(d["trend"]["yMax"] % d["trend"]["yTicks"], 0)

    def test_empty(self):
        d = stats.overview(Ticket.objects.none(), 7)
        self.assertEqual(d["sla_pct"], None)
        self.assertIsNone(d["kpis"][0]["delta"])

    def test_helpers(self):
        self.assertEqual(stats.parse_range("30"), 30)
        self.assertEqual(stats.parse_range("abc"), 15)
        self.assertEqual(stats.parse_range("9"), 15)
        self.assertEqual(stats.nice_max(0), 4)
        self.assertEqual(stats.nice_max(23), 24)
        self.assertEqual(stats.initials(self.op), "OO")
        self.assertEqual(stats.pct_change(5, 0), None)


# ------------------------------------------------------------------ pages
class PageTests(Base):
    def seed(self):
        self.inc = self.incident(priority="P1", category="Network", client="WeCrew", ci_name="fw-01", fingerprint="f:1")
        services.assign(self.inc, self.op, self.op)
        self.prb = services.create_ticket(kind="problem", title="Flapping")
        services.link_problem(self.inc, self.prb, self.op)
        self.chg = services.create_ticket(kind="change", title="Upgrade fw", planned_start=timezone.now() + timedelta(days=1),
                                          planned_end=timezone.now() + timedelta(days=1, hours=1), risk="high")
        services.add_ci(self.chg, "fw-01")
        self.item = CatalogItem.objects.create(name="VPN access", category="Access", fulfilment_hours=8)
        self.req = services.request_from_catalog(self.item, self.op)

    def test_pages_render_empty(self):
        c = self.login(self.viewer)
        for name in ("incidents", "tickets", "problems", "changes", "catalog", "sla"):
            r = c.get(reverse(f"servicedesk:{name}"))
            self.assertEqual(r.status_code, 200, name)
        self.assertContains(c.get(reverse("servicedesk:incidents")), "No open P1 incidents")
        self.assertContains(c.get(reverse("servicedesk:catalog")), "The service catalog is empty")
        self.assertRedirects(c.get("/service-desk/"), reverse("servicedesk:incidents"))

    def test_required_url_paths(self):
        self.assertEqual(reverse("servicedesk:tickets"), "/service-desk/tickets/")
        self.assertEqual(reverse("servicedesk:incidents"), "/service-desk/incidents/")
        for n in ("problems", "changes", "catalog"):
            reverse(f"servicedesk:{n}")

    def test_pages_render_with_data(self):
        self.seed()
        c = self.login(self.viewer)
        r = c.get(reverse("servicedesk:incidents"))
        self.assertContains(r, self.inc.number)
        self.assertContains(r, "Total Incidents")
        self.assertContains(r, 'id="d-trend"')
        for tab in ("all", "mine", "unassigned", "major", "sla"):
            r = c.get(reverse("servicedesk:incidents"), {"tab": tab, "range": "30"})
            self.assertEqual(r.status_code, 200, tab)
        self.assertContains(c.get(reverse("servicedesk:incidents"), {"tab": "major"}), self.inc.number)
        self.assertNotContains(c.get(reverse("servicedesk:incidents"), {"tab": "unassigned"}), self.inc.number)
        r = c.get(reverse("servicedesk:tickets"))
        for t in (self.inc, self.prb, self.chg, self.req):
            self.assertContains(r, t.number)
        r = c.get(reverse("servicedesk:tickets"), {"kind": "change"})
        self.assertContains(r, self.chg.number)
        self.assertNotContains(r, self.inc.number)
        self.assertContains(c.get(reverse("servicedesk:problems")), self.prb.number)
        r = c.get(reverse("servicedesk:changes"))
        self.assertContains(r, "Not submitted")
        self.assertContains(r, "Upcoming Windows")
        self.assertContains(c.get(reverse("servicedesk:catalog")), "VPN access")
        for t in (self.inc, self.prb, self.chg, self.req):
            r = c.get(t.get_absolute_url())
            self.assertContains(r, t.title)
            self.assertNotContains(r, 'name="to"')   # viewers get no workflow buttons
        self.assertContains(c.get(self.prb.get_absolute_url()), self.inc.number)
        self.assertContains(c.get(self.chg.get_absolute_url()), "fw-01")

    def test_detail_urls(self):
        self.seed()
        c = self.login(self.viewer)
        self.assertEqual(self.inc.get_absolute_url(), f"/service-desk/incidents/{self.inc.number}/")
        self.assertEqual(self.req.get_absolute_url(), f"/service-desk/tickets/{self.req.number}/")
        self.assertEqual(c.get(reverse("servicedesk:detail", args=[self.chg.number])).status_code, 200)
        self.assertRedirects(c.get(f"/service-desk/incidents/{self.chg.number}/"), self.chg.get_absolute_url())
        self.assertEqual(c.get(f"/service-desk/incidents/{self.inc.number.lower()}/").status_code, 200)
        self.assertEqual(c.get("/service-desk/incidents/INC-9999/").status_code, 404)
        self.assertEqual(c.get(f"/service-desk/bogus/{self.inc.number}/").status_code, 404)

    def test_filters(self):
        self.seed()
        other = self.incident(title="Printer jam", priority="P4", category="Hardware", client="Mirae")
        c = self.login(self.viewer)
        url = reverse("servicedesk:tickets")
        self.assertNotContains(c.get(url, {"q": "printer"}), self.inc.number)
        self.assertContains(c.get(url, {"q": "printer"}), other.number)
        self.assertContains(c.get(url, {"q": other.number}), other.number)
        self.assertNotContains(c.get(url, {"priority": "P1"}), other.number)
        self.assertNotContains(c.get(url, {"client": "WeCrew"}), other.number)
        self.assertNotContains(c.get(url, {"assignee": str(self.op.pk)}), other.number)
        self.assertContains(c.get(url, {"assignee": "none", "kind": "incident"}), other.number)
        self.assertContains(c.get(url, {"category": "Hardware"}), other.number)
        self.assertNotContains(c.get(url, {"status": "done"}), other.number)
        self.assertEqual(c.get(url, {"per": "abc", "page": "999"}).status_code, 200)
        r = c.get(reverse("servicedesk:incidents"), {"tab": "all", "client": "Mirae"})
        self.assertContains(r, other.number)
        self.assertNotContains(r, self.inc.number)
        r = c.get(reverse("servicedesk:changes"), {"approval": "pending"})
        self.assertNotContains(r, self.chg.number)
        r = c.get(reverse("servicedesk:changes"), {"window": "upcoming"})
        self.assertContains(r, self.chg.number)

    def test_csv_export(self):
        self.seed()
        self.incident(title="=HYPERLINK(\"http://evil\")")
        c = self.login(self.viewer)
        r = c.get(reverse("servicedesk:export"), {"kind": "incident"})
        self.assertEqual(r["Content-Type"], "text/csv")
        rows = list(csv.reader(io.StringIO(r.content.decode())))
        self.assertEqual(rows[0][0], "number")
        self.assertEqual(len(rows), 3)
        self.assertTrue(any(row[2].startswith("'=") for row in rows[1:]))
        r = c.get(reverse("servicedesk:export"), {"tab": "major"})
        self.assertEqual(len(list(csv.reader(io.StringIO(r.content.decode())))), 2)

    def test_site_scoping(self):
        Site.objects.create(name="Mumbai", code="mum")
        Site.objects.create(name="DR", code="dr")
        a = self.incident(title="Mumbai issue", site="Mumbai")
        b = self.incident(title="DR issue", site="DR")
        g = self.incident(title="Global issue", site="All Sites")
        u = User.objects.create_user("mum-op")
        Membership.objects.create(user=u, site=Site.objects.get(name="Mumbai"), role="operator")
        c = self.login(u)
        r = c.get(reverse("servicedesk:tickets"))
        self.assertContains(r, a.number)
        self.assertContains(r, g.number)
        self.assertNotContains(r, b.number)
        self.assertEqual(c.get(b.get_absolute_url()).status_code, 404)
        self.assertEqual(c.post(reverse("servicedesk:comment", args=[b.number]), {"body": "x"}).status_code, 404)
        c.post(reverse("servicedesk:comment", args=[a.number]), {"body": "on my site"})
        self.assertTrue(a.timeline.filter(kind="comment").exists())
        # header site picker narrows the list
        r = self.login(self.viewer).get(reverse("servicedesk:tickets"), {"site": "DR"})
        self.assertContains(r, b.number)
        self.assertNotContains(r, a.number)


# ------------------------------------------------------------------ permissions + mutations
class MutationTests(Base):
    def test_viewer_cannot_mutate(self):
        t = self.incident()
        c = self.login(self.viewer)
        self.assertEqual(c.get(reverse("servicedesk:create")).status_code, 403)
        self.assertEqual(c.get(reverse("servicedesk:edit", args=[t.number])).status_code, 403)
        posts = [("transition", {"to": "acknowledged"}), ("assign", {"assignee": "me"}), ("priority", {"priority": "P1"}),
                 ("comment", {"body": "hi"}), ("link", {"problem": ""}), ("add_ci", {"ci_name": "x"}), ("delete", {})]
        for name, data in posts:
            r = c.post(reverse(f"servicedesk:{name}", args=[t.number]), data)
            self.assertIn(r.status_code, (302, 403), name)
        r = c.post(reverse("servicedesk:create"), {"kind": "incident", "title": "x", "priority": "P3"})
        self.assertIn(r.status_code, (302, 403))
        t.refresh_from_db()
        self.assertEqual((t.status, t.assignee, t.priority), ("new", None, "P2"))
        self.assertFalse(t.timeline.filter(kind="comment").exists())
        self.assertEqual(Ticket.objects.count(), 1)

    def test_get_on_mutation_urls_is_rejected(self):
        t = self.incident()
        c = self.login(self.op)
        for name in ("transition", "assign", "priority", "comment", "link", "delete"):
            self.assertEqual(c.get(reverse(f"servicedesk:{name}", args=[t.number])).status_code, 405, name)

    def test_csrf_enforced(self):
        t = self.incident()
        c = self.login(self.op, csrf=True)
        r = c.post(reverse("servicedesk:transition", args=[t.number]), {"to": "acknowledged"})
        self.assertEqual(r.status_code, 403)
        t.refresh_from_db()
        self.assertEqual(t.status, "new")
        # with the token it works
        c.get(t.get_absolute_url())
        token = c.cookies["csrftoken"].value
        r = c.post(reverse("servicedesk:transition", args=[t.number]), {"to": "acknowledged", "csrfmiddlewaretoken": token})
        self.assertEqual(r.status_code, 302)
        t.refresh_from_db()
        self.assertEqual(t.status, "acknowledged")

    def test_operator_create_and_edit(self):
        c = self.login(self.op)
        self.assertEqual(c.get(reverse("servicedesk:create"), {"kind": "change"}).status_code, 200)
        r = c.post(reverse("servicedesk:create"), {"kind": "incident", "title": "VPN down", "priority": "P2",
                                                   "category": "Network", "assignee": self.op2.pk, "description": "d"})
        t = Ticket.objects.get()
        self.assertRedirects(r, t.get_absolute_url())
        self.assertEqual((t.number, t.reporter, t.assignee, t.source), ("INC-1001", self.op, self.op2, "manual"))
        self.assertTrue(AuditEvent.objects.filter(action="create", object_id=str(t.pk)).exists())
        r = c.post(reverse("servicedesk:edit", args=[t.number]), {
            "title": "VPN down for all", "priority": "P1", "category": "Network", "assignee": self.op.pk, "description": "d"})
        self.assertRedirects(r, t.get_absolute_url())
        t.refresh_from_db()
        self.assertEqual((t.title, t.priority, t.assignee, t.status), ("VPN down for all", "P1", self.op, "new"))
        self.assertTrue(t.timeline.filter(kind="priority").exists())
        self.assertTrue(t.timeline.filter(kind="edit", body__contains="Title").exists())
        self.assertEqual(t.resolution_due - t.opened_at, timedelta(minutes=240))
        self.assertTrue(AuditEvent.objects.filter(action="update", object_id=str(t.pk)).exists())

    def test_create_change_validates_window(self):
        c = self.login(self.op)
        start = (timezone.localtime() + timedelta(days=2)).strftime("%Y-%m-%dT%H:%M")
        r = c.post(reverse("servicedesk:create"), {"kind": "change", "title": "x", "priority": "P3",
                                                   "planned_start": start, "planned_end": start})
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "must be after the planned start")
        self.assertEqual(Ticket.objects.count(), 0)

    def test_create_requires_site_permission(self):
        Site.objects.create(name="Mumbai", code="mum")
        Site.objects.create(name="DR", code="dr")
        u = User.objects.create_user("mum-op")
        Membership.objects.create(user=u, site=Site.objects.get(name="Mumbai"), role="operator")
        c = self.login(u)
        r = c.post(reverse("servicedesk:create"), {"kind": "incident", "title": "x", "priority": "P3", "site": "DR"})
        self.assertContains(r, "cannot raise")
        c.post(reverse("servicedesk:create"), {"kind": "incident", "title": "x", "priority": "P3", "site": "Mumbai"})
        self.assertEqual(Ticket.objects.get().site, "Mumbai")

    def test_operator_actions_with_audit(self):
        t = self.incident()
        c = self.login(self.op)
        r = c.post(reverse("servicedesk:transition", args=[t.number]), {"to": "acknowledged", "note": "on it"})
        self.assertRedirects(r, t.get_absolute_url())
        r = c.post(reverse("servicedesk:transition", args=[t.number]), {"to": "closed"}, follow=True)
        self.assertContains(r, "cannot move from")
        self.assertTrue(AuditEvent.objects.filter(action="transition", result="denied").exists())
        c.post(reverse("servicedesk:assign", args=[t.number]), {"assignee": "me"})
        c.post(reverse("servicedesk:priority", args=[t.number]), {"priority": "P1"})
        c.post(reverse("servicedesk:comment", args=[t.number]), {"body": "Restarted the VPN concentrator"})
        t.refresh_from_db()
        self.assertEqual((t.status, t.assignee, t.priority), ("acknowledged", self.op, "P1"))
        self.assertTrue(t.timeline.filter(kind="comment", author=self.op).exists())
        actions = set(AuditEvent.objects.filter(object_id=str(t.pk)).values_list("action", flat=True))
        self.assertTrue({"transition", "assign", "priority", "comment"} <= actions)
        r = c.post(reverse("servicedesk:assign", args=[t.number]), {"assignee": str(self.viewer.pk)}, follow=True)
        self.assertContains(r, "Choose an active user")
        r = c.post(reverse("servicedesk:comment", args=[t.number]), {"body": ""}, follow=True)
        self.assertContains(r, "cannot be empty")
        r = c.post(reverse("servicedesk:priority", args=[t.number]), {"priority": "P7"}, follow=True)
        self.assertContains(r, "Unknown priority")

    def test_link_views(self):
        inc = self.incident()
        prb = services.create_ticket(kind="problem", title="p")
        c = self.login(self.op)
        c.post(reverse("servicedesk:link", args=[inc.number]), {"problem": prb.number})
        self.assertEqual(Ticket.objects.get(pk=inc.pk).problem, prb)
        c.post(reverse("servicedesk:link", args=[prb.number]), {"incident": inc.number, "unlink": "1"})
        self.assertIsNone(Ticket.objects.get(pk=inc.pk).problem)
        c.post(reverse("servicedesk:link", args=[prb.number]), {"incident": inc.number})
        self.assertEqual(Ticket.objects.get(pk=inc.pk).problem, prb)
        r = c.post(reverse("servicedesk:link", args=[prb.number]), {"incident": "INC-4040"}, follow=True)
        self.assertContains(r, "No incident INC-4040")
        self.assertTrue(AuditEvent.objects.filter(action="link").exists())

    def test_ci_views(self):
        chg = services.create_ticket(kind="change", title="c")
        c = self.login(self.op)
        c.post(reverse("servicedesk:add_ci", args=[chg.number]), {"ci_name": "fw-01", "note": "primary"})
        ci = TicketCI.objects.get()
        self.assertEqual((ci.ticket, ci.note), (chg, "primary"))
        c.post(reverse("servicedesk:remove_ci", args=[chg.number, ci.pk]))
        self.assertFalse(TicketCI.objects.exists())
        self.assertTrue(AuditEvent.objects.filter(action="unlink").exists())

    def test_delete_needs_admin(self):
        t = self.incident()
        r = self.login(self.op).post(reverse("servicedesk:delete", args=[t.number]))
        self.assertIn(r.status_code, (302, 403))
        self.assertTrue(Ticket.objects.filter(pk=t.pk).exists())
        r = self.login(self.admin).post(reverse("servicedesk:delete", args=[t.number]))
        self.assertRedirects(r, reverse("servicedesk:incidents"))
        self.assertFalse(Ticket.objects.filter(pk=t.pk).exists())
        self.assertFalse(TimelineEntry.objects.filter(ticket_id=t.pk).exists())
        self.assertTrue(AuditEvent.objects.filter(action="delete", details__number=t.number).exists())

    def test_operator_sees_actions_viewer_does_not(self):
        t = self.incident()
        self.assertContains(self.login(self.op).get(t.get_absolute_url()), 'value="acknowledged"')
        self.assertNotContains(self.login(self.op).get(t.get_absolute_url()), ">Delete<")
        self.assertContains(self.login(self.admin).get(t.get_absolute_url()), "Delete")


class CatalogTests(Base):
    def test_request_creates_ticket(self):
        item = CatalogItem.objects.create(name="Laptop", fulfilment_hours=48, category="Hardware")
        c = self.login(self.op)
        self.assertEqual(c.get(reverse("servicedesk:catalog_request", args=[item.pk])).status_code, 200)
        r = c.post(reverse("servicedesk:catalog_request", args=[item.pk]), {"details": "14 inch", "client": "WeCrew"})
        t = Ticket.objects.get()
        self.assertRedirects(r, t.get_absolute_url())
        self.assertEqual((t.kind, t.number, t.catalog_item, t.client, t.source), ("request", "REQ-1001", item, "WeCrew", "catalog"))
        self.assertTrue(AuditEvent.objects.filter(action="create", object_id=str(t.pk)).exists())
        self.assertContains(c.get(reverse("servicedesk:catalog")), t.number)   # my recent requests

    def test_viewer_cannot_request_and_inactive_items_hidden(self):
        item = CatalogItem.objects.create(name="Laptop")
        off = CatalogItem.objects.create(name="Fax machine", active=False)
        c = self.login(self.viewer)
        self.assertEqual(c.get(reverse("servicedesk:catalog_request", args=[item.pk])).status_code, 403)
        r = c.get(reverse("servicedesk:catalog"))
        self.assertNotContains(r, "Fax machine")
        self.assertNotContains(r, reverse("servicedesk:catalog_request", args=[item.pk]))
        self.assertEqual(self.login(self.op).get(reverse("servicedesk:catalog_request", args=[off.pk])).status_code, 404)

    def test_manage_items(self):
        c = self.login(self.op)   # configure == operate rank
        r = c.post(reverse("servicedesk:catalog_new"), {"name": "VPN", "category": "Access", "description": "d",
                                                        "fulfilment_hours": 8, "default_priority": "P3", "active": "on"})
        self.assertRedirects(r, reverse("servicedesk:catalog"))
        item = CatalogItem.objects.get()
        r = c.post(reverse("servicedesk:catalog_new"), {"name": "vpn", "fulfilment_hours": 8, "default_priority": "P3"})
        self.assertContains(r, "already exists")
        c.post(reverse("servicedesk:catalog_edit", args=[item.pk]), {"name": "VPN access", "fulfilment_hours": 4, "default_priority": "P3"})
        item.refresh_from_db()
        self.assertEqual((item.name, item.fulfilment_hours, item.active), ("VPN access", 4, False))
        self.assertEqual(self.login(self.viewer).get(reverse("servicedesk:catalog_new")).status_code, 403)
        c.post(reverse("servicedesk:catalog_delete", args=[item.pk]))
        self.assertTrue(CatalogItem.objects.exists())   # operators cannot delete
        self.login(self.admin).post(reverse("servicedesk:catalog_delete", args=[item.pk]))
        self.assertFalse(CatalogItem.objects.exists())
        self.assertEqual(set(AuditEvent.objects.values_list("action", flat=True)), {"create", "update", "delete"})


class SlaPolicyPageTests(Base):
    def test_admin_edits_policy(self):
        p = SlaPolicy.objects.get(priority="P1")
        data = {"pk": p.pk, f"p{p.pk}-name": "Critical", f"p{p.pk}-response_minutes": 10,
                f"p{p.pk}-resolution_minutes": 120, f"p{p.pk}-active": "on"}
        r = self.login(self.op).post(reverse("servicedesk:sla"), data)
        self.assertRedirects(r, reverse("servicedesk:sla"))
        p.refresh_from_db()
        self.assertEqual(p.response_minutes, 15)   # operator: refused
        self.login(self.admin).post(reverse("servicedesk:sla"), data)
        p.refresh_from_db()
        self.assertEqual((p.response_minutes, p.resolution_minutes), (10, 120))
        self.assertTrue(AuditEvent.objects.filter(action="update", object_type="servicedesk.slapolicy").exists())
        data[f"p{p.pk}-resolution_minutes"] = 5
        r = self.login(self.admin).post(reverse("servicedesk:sla"), data)
        self.assertContains(r, "must not be shorter")


class SeedTests(Base):
    def test_seed_is_idempotent_and_marked(self):
        out = io.StringIO()
        call_command("seed_servicedesk", stdout=out)
        n = Ticket.objects.count()
        self.assertGreater(n, 50)
        self.assertTrue(all(t.description.startswith("[Example]") and t.fingerprint.startswith("example:") for t in Ticket.objects.all()))
        self.assertTrue(set(Ticket.objects.values_list("kind", flat=True)) == {"incident", "problem", "change", "request"})
        recent = Ticket.objects.filter(kind="incident", opened_at__gte=timezone.now() - timedelta(days=15)).count()
        self.assertGreaterEqual(recent, 40)
        self.assertTrue(Ticket.objects.filter(kind="incident", priority="P1").open().exists())
        self.assertFalse(Ticket.objects.filter(opened_at__gt=timezone.now()).exists())
        self.assertFalse(TimelineEntry.objects.filter(created_at__gt=timezone.now()).exists())
        call_command("seed_servicedesk", stdout=out)
        self.assertEqual(Ticket.objects.count(), n)
        self.assertEqual(CatalogItem.objects.count(), 8)
        self.assertFalse(User.objects.filter(username__startswith="example.").exclude(password__startswith="!").exists())
        self.assertEqual(self.login(self.viewer).get(reverse("servicedesk:incidents")).status_code, 200)
        call_command("seed_servicedesk", "--remove", stdout=out)
        self.assertEqual(Ticket.objects.count(), 0)
        self.assertEqual(CatalogItem.objects.count(), 0)
        self.assertFalse(User.objects.filter(username__startswith="example.").exists())
