from datetime import date, datetime, time, timedelta
from unittest import mock

from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.test import Client, TestCase
from django.urls import reverse
from django.utils import timezone

from core import jobs
from core.models import AuditEvent, Event, Membership
from domainmonitor.models import Domain
from urlchecker.models import UrlCheck

from . import services
from .models import ChecklistItem, Holiday, Mode, Run, RunItem
from .services import IST

MONDAY = date(2026, 11, 2)  # a Monday that is not a holiday


def ist(d, h, m=0):
    return datetime.combine(d, time(h, m), tzinfo=IST)


def make_mode(code="BOD", **kw):
    defaults = {"name": {"BOD": "Beginning of Day", "EOD": "End of Day", "ADP": "After-Day"}[code],
                "window_start": time(7, 0), "window_end": time(9, 0), "auto_run_time": time(7, 15),
                "refresh_checks": False}
    defaults.update(kw)
    return Mode.objects.create(code=code, **defaults)


def url_check(name, status="online", checked=True, **kw):
    return UrlCheck.objects.create(name=name, url="https://example.com/", last_status=status,
                                   last_checked_at=timezone.now() if checked else None, last_response_ms=120, **kw)


def users():
    viewer = User.objects.create_user("viewer", password="pw")
    operator = User.objects.create_user("operator", password="pw", is_staff=True)
    admin = User.objects.create_user("boss", password="pw")
    Membership.objects.create(user=admin, site=None, role="admin")
    return viewer, operator, admin


def client_for(user):
    c = Client()
    c.force_login(user)
    return c


# ------------------------------------------------------------------ models and status rules
class StatusRuleTests(TestCase):
    def ri(self, status, critical=True):
        return RunItem(status=status, critical=critical, name="x", kind="url_check")

    def test_compute_status(self):
        c = services.compute_status
        self.assertEqual(c([self.ri("ok"), self.ri("signed_off")]), "pass")
        self.assertEqual(c([self.ri("ok"), self.ri("warning")]), "warn")
        self.assertEqual(c([self.ri("ok"), self.ri("unknown")]), "warn")
        self.assertEqual(c([self.ri("ok"), self.ri("pending")]), "warn")
        self.assertEqual(c([self.ri("ok"), self.ri("critical", critical=False)]), "warn")
        self.assertEqual(c([self.ri("warning"), self.ri("critical", critical=True)]), "fail")
        self.assertEqual(c([]), "pass")

    def test_codes(self):
        self.assertEqual([self.ri(s).code for s in ("ok", "signed_off", "warning", "critical", "unknown", "pending")],
                         [0, 0, 1, 2, 3, 5])

    def test_counts_and_summary(self):
        items = [self.ri("ok"), self.ri("signed_off"), self.ri("critical"), self.ri("pending")]
        c = services.counts(items)
        self.assertEqual((c["total"], c["done"], c["critical"], c["pending"]), (4, 2, 1, 1))
        self.assertEqual(services.summarize(items), "2/4 OK, 1 critical, 1 pending sign-off")

    def test_url_status_mapping(self):
        self.assertEqual(services.status_of("url_check", url_check("a", "online"))[0], "ok")
        self.assertEqual(services.status_of("url_check", url_check("b", "degraded"))[0], "warning")
        self.assertEqual(services.status_of("url_check", url_check("c", "down"))[0], "critical")
        self.assertEqual(services.status_of("url_check", url_check("d", "unknown", checked=False))[0], "unknown")
        self.assertEqual(services.status_of("url_check", url_check("e", "online", enabled=False))[0], "unknown")
        self.assertEqual(services.status_of("url_check", None), ("unknown", "URL check not found"))

    def test_domain_status_mapping(self):
        now = timezone.now()
        mk = lambda host, **kw: Domain.objects.create(tenant_key="default", site_key="All Sites", hostname=host,  # noqa: E731
                                                      last_checked_at=now, **kw)
        self.assertEqual(services.status_of("domain", mk("a.example.com", status="up", dns_status="Resolved", ssl_status="Valid"))[0], "ok")
        self.assertEqual(services.status_of("domain", mk("b.example.com", status="up", dns_status="Resolved", ssl_status="Expiring"))[0], "warning")
        self.assertEqual(services.status_of("domain", mk("c.example.com", status="down", dns_status="Failed"))[0], "critical")
        self.assertEqual(services.status_of("domain", mk("d.example.com", status="up", dns_status="Resolved", ssl_status="Expired"))[0], "critical")
        self.assertEqual(services.status_of("domain", Domain(hostname="e.example.com", status="unknown"))[0], "unknown")
        self.assertEqual(services.status_of("domain", None)[0], "unknown")

    def test_tcp_status_mapping(self):
        from tcpcheck.models import TcpCheck
        t = TcpCheck.objects.create(name="Gateway", host="10.0.0.1", port=22, last_status="down",
                                    last_checked_at=timezone.now(), last_error="refused")
        st, detail = services.status_of("tcp_check", t)
        self.assertEqual(st, "critical")
        self.assertIn("refused", detail)

    def test_resolver_batches_and_tenant(self):
        url_check("Mine")
        UrlCheck.objects.create(tenant_key="other", name="Theirs", url="https://example.org/", last_status="online",
                                last_checked_at=timezone.now())
        mode = make_mode()
        a = ChecklistItem.objects.create(mode=mode, name="a", kind="url_check", ref_name="Mine")
        b = ChecklistItem.objects.create(mode=mode, name="b", kind="url_check", ref_name="Theirs")
        r = services.Resolver([a, b])
        self.assertIsNotNone(r.get("url_check", "Mine"))
        self.assertIsNone(r.get("url_check", "Theirs"))  # other tenant is invisible
        self.assertTrue(r.link("url_check", "Mine").startswith("/"))

    def test_missing_module_is_unknown(self):
        mode = make_mode()
        item = ChecklistItem.objects.create(mode=mode, name="tcp", kind="tcp_check", ref_name="x")
        with mock.patch.object(services, "_model", return_value=None):
            st, detail = services.live_status(item)
        self.assertEqual(st, "unknown")
        self.assertIn("not available", detail)


# ------------------------------------------------------------------ trading calendar
class CalendarTests(TestCase):
    def test_weekend_and_holidays(self):
        self.assertEqual(services.trading_day(MONDAY), (True, "Trading day"))
        self.assertFalse(services.trading_day(date(2026, 11, 1))[0])  # Sunday
        Holiday.objects.create(exchange="NSE", date=MONDAY, description="Test holiday")
        ok, reason = services.trading_day(MONDAY)
        self.assertFalse(ok)
        self.assertIn("Test holiday", reason)

    def test_only_all_and_nse_close_the_market(self):
        Holiday.objects.create(exchange="BSE", date=MONDAY, description="BSE only")
        self.assertTrue(services.trading_day(MONDAY)[0])
        Holiday.objects.create(exchange="ALL", date=MONDAY, description="Everyone")
        self.assertFalse(services.trading_day(MONDAY)[0])

    def test_next_trading_day_skips_holidays(self):
        Holiday.objects.create(exchange="NSE", date=MONDAY, description="h")
        self.assertEqual(services.next_trading_day(date(2026, 10, 30)), MONDAY + timedelta(days=1))

    def test_phase_and_window(self):
        self.assertEqual(services.market_phase(ist(MONDAY, 7, 30))["key"], "bod")
        self.assertEqual(services.market_phase(ist(MONDAY, 12))["key"], "trading")
        self.assertEqual(services.market_phase(ist(MONDAY, 15, 45))["key"], "eod")
        self.assertEqual(services.market_phase(ist(MONDAY, 18))["key"], "closed")
        mode = make_mode()
        self.assertEqual(services.window_state(mode, ist(MONDAY, 6)), "upcoming")
        self.assertEqual(services.window_state(mode, ist(MONDAY, 8)), "open")
        self.assertEqual(services.window_state(mode, ist(MONDAY, 10)), "closed")
        self.assertEqual(services.window_state(mode, ist(date(2026, 11, 1), 8)), "no_trading")


# ------------------------------------------------------------------ runs
class RunTests(TestCase):
    def setUp(self):
        self.mode = make_mode()
        self.ok = url_check("Portal OK")
        self.slow = url_check("Portal slow", "degraded", last_error="Slow response")
        self.down = url_check("Portal down", "down", last_error="HTTP 503")
        self.op = User.objects.create_user("op", is_staff=True)

    def add(self, name, kind="url_check", ref="", critical=True, order=10):
        return ChecklistItem.objects.create(mode=self.mode, name=name, kind=kind, ref_name=ref, critical=critical, order=order)

    def test_pass_run_emits_ok_event(self):
        self.add("ok", ref="Portal OK")
        run = services.start_run(self.mode, user=self.op)
        self.assertEqual(run.status, "pass")
        self.assertIsNotNone(run.finished_at)
        self.assertEqual(run.triggered_by_name, "op")
        ev = Event.objects.get(source="bodeod")
        self.assertEqual(ev.severity, "ok")
        self.assertEqual(ev.fingerprint, f"bodeod:mode:{self.mode.pk}")

    def test_fail_and_warn_runs(self):
        self.add("ok", ref="Portal OK", order=10)
        self.add("down", ref="Portal down", order=20)
        run = services.start_run(self.mode)
        self.assertEqual(run.status, "fail")
        self.assertEqual(Event.objects.filter(source="bodeod").latest("occurred_at").severity, "critical")
        ChecklistItem.objects.filter(name="down").update(critical=False)
        self.add("slow", ref="Portal slow", order=30)
        run2 = services.start_run(self.mode)
        self.assertEqual(run2.status, "warn")
        self.assertEqual(Event.objects.filter(source="bodeod").latest("occurred_at").severity, "warning")
        self.assertEqual([r.status for r in run2.results.all()], ["ok", "critical", "warning"])

    def test_missing_reference_and_manual_pending(self):
        self.add("ghost", ref="Does not exist", order=10)
        self.add("feed", kind="manual", order=20)
        run = services.start_run(self.mode)
        res = {r.name: r for r in run.results.all()}
        self.assertEqual(res["ghost"].status, "unknown")
        self.assertEqual(res["feed"].status, "pending")
        self.assertEqual(run.status, "warn")

    def test_disabled_items_are_skipped_and_snapshot_kept(self):
        self.add("ok", ref="Portal OK")
        ChecklistItem.objects.create(mode=self.mode, name="off", kind="url_check", ref_name="Portal down", enabled=False)
        run = services.start_run(self.mode)
        self.assertEqual(run.results.count(), 1)
        ChecklistItem.objects.filter(name="ok").delete()
        r = run.results.get()
        self.assertIsNone(r.item_id)
        self.assertEqual((r.name, r.ref_name), ("ok", "Portal OK"))

    def test_refresh_reruns_referenced_checks_once(self):
        self.add("a", ref="Portal OK", order=10)
        self.add("b", ref="Portal OK", order=20)
        self.add("dom", kind="domain", ref="nse.example.com", order=30)
        Domain.objects.create(tenant_key="default", site_key="All Sites", hostname="nse.example.com")
        with mock.patch("probes.runner.run_url_checks") as urls, mock.patch("probes.runner.run_domain_checks") as doms:
            run = services.start_run(self.mode, refresh=True)
        urls.assert_called_once()
        self.assertEqual([c.name for c in urls.call_args[0][0]], ["Portal OK"])
        doms.assert_called_once()
        self.assertTrue(run.refreshed)

    def test_refresh_tcp_checks(self):
        from tcpcheck.models import TcpCheck
        TcpCheck.objects.create(name="SSH", host="10.0.0.5", port=22, last_status="online", last_checked_at=timezone.now())
        self.add("ssh", kind="tcp_check", ref="SSH")
        with mock.patch("tcpcheck.services.run_checks") as tcp:
            run = services.start_run(self.mode, refresh=True)
        tcp.assert_called_once()
        self.assertEqual(run.status, "pass")

    def test_refresh_errors_do_not_break_the_run(self):
        self.add("a", ref="Portal OK")
        with mock.patch("probes.runner.run_url_checks", side_effect=RuntimeError("boom")):
            run = services.start_run(self.mode, refresh=True)
        self.assertEqual(run.status, "pass")

    def test_busy_mode_refuses_second_run(self):
        Run.objects.create(mode=self.mode, trading_date=MONDAY, status="running")
        with self.assertRaises(services.RunError):
            services.start_run(self.mode)

    def test_sign_off_completes_run(self):
        self.add("ok", ref="Portal OK", order=10)
        self.add("feed", kind="manual", order=20)
        run = services.start_run(self.mode)
        self.assertEqual(run.status, "warn")
        pending = run.results.get(name="feed")
        with self.assertRaises(services.RunError):
            services.sign_off(pending, self.op, "  ")
        with self.assertRaises(services.RunError):
            services.sign_off(run.results.get(name="ok"), self.op, "note")
        services.sign_off(pending, self.op, "Feed handler connected")
        run.refresh_from_db()
        pending.refresh_from_db()
        self.assertEqual(run.status, "pass")
        self.assertEqual((pending.status, pending.signed_off_by, pending.note), ("signed_off", self.op, "Feed handler connected"))
        self.assertEqual(Event.objects.filter(source="bodeod").latest("occurred_at").severity, "ok")
        with self.assertRaises(services.RunError):
            services.sign_off(pending, self.op, "again")

    def test_sign_off_only_on_latest_run_of_today(self):
        self.add("feed", kind="manual")
        old = services.start_run(self.mode, trading_date=services.today_ist() - timedelta(days=1))
        with self.assertRaises(services.RunError):
            services.sign_off(old.results.get(), self.op, "late")
        first = services.start_run(self.mode)
        services.start_run(self.mode)
        with self.assertRaises(services.RunError):
            services.sign_off(first.results.get(), self.op, "superseded")

    def test_sign_off_carries_forward_within_the_day(self):
        self.add("feed", kind="manual")
        run = services.start_run(self.mode)
        services.sign_off(run.results.get(), self.op, "checked")
        again = services.start_run(self.mode)
        r = again.results.get()
        self.assertEqual(r.status, "signed_off")
        self.assertEqual(r.signed_off_by_name, "op")
        self.assertEqual(again.status, "pass")
        tomorrow = services.start_run(self.mode, trading_date=services.today_ist() + timedelta(days=1))
        self.assertEqual(tomorrow.results.get().status, "pending")

    def test_revalidate_updates_statuses(self):
        self.add("down", ref="Portal down")
        run = services.start_run(self.mode)
        self.assertEqual(run.status, "fail")
        UrlCheck.objects.filter(pk=self.down.pk).update(last_status="online", last_error="")
        with mock.patch("probes.runner.run_url_checks"):
            services.revalidate(run, refresh=True)
        run.refresh_from_db()
        self.assertEqual(run.status, "pass")

    def test_finalize_stale_runs(self):
        run = Run.objects.create(mode=self.mode, trading_date=MONDAY, status="running",
                                 started_at=timezone.now() - timedelta(hours=2))
        RunItem.objects.create(run=run, name="x", kind="url_check", status="pending")
        self.assertEqual(services.finalize_stale(), 1)
        run.refresh_from_db()
        self.assertEqual(run.status, "warn")
        self.assertEqual(run.results.get().status, "unknown")


# ------------------------------------------------------------------ scheduler
class SchedulerTests(TestCase):
    def setUp(self):
        self.bod = make_mode("BOD")
        self.eod = make_mode("EOD", window_start=time(15, 30), window_end=time(16, 0), auto_run_time=time(15, 40))
        url_check("Portal")
        ChecklistItem.objects.create(mode=self.bod, name="portal", ref_name="Portal")
        ChecklistItem.objects.create(mode=self.eod, name="portal", ref_name="Portal")

    def test_job_registered(self):
        self.assertIn("bodeod.auto_run", jobs.JOBS)
        self.assertEqual(jobs.JOBS["bodeod.auto_run"]["interval"], 60)

    def test_starts_each_mode_once_at_its_time(self):
        self.assertIsNone(services.auto_run(ist(MONDAY, 7, 10)))
        self.assertEqual(Run.objects.count(), 0)
        out = services.auto_run(ist(MONDAY, 7, 16))
        self.assertIn("BOD", out)
        run = Run.objects.get()
        self.assertEqual((run.mode, run.trigger, run.trading_date, run.by_label), (self.bod, "scheduler", MONDAY, "scheduler"))
        services.auto_run(ist(MONDAY, 7, 17))
        self.assertEqual(Run.objects.count(), 1)
        services.auto_run(ist(MONDAY, 15, 41))
        self.assertEqual(Run.objects.filter(mode=self.eod).count(), 1)

    def test_manual_run_does_not_block_scheduler(self):
        services.start_run(self.bod, trading_date=MONDAY, now=ist(MONDAY, 7, 0))
        services.auto_run(ist(MONDAY, 7, 16))
        self.assertEqual(Run.objects.filter(mode=self.bod, trigger="scheduler").count(), 1)

    def test_no_runs_on_weekend_or_holiday(self):
        self.assertIsNone(services.auto_run(ist(date(2026, 11, 1), 7, 16)))  # Sunday
        Holiday.objects.create(exchange="NSE", date=MONDAY, description="h")
        self.assertIsNone(services.auto_run(ist(MONDAY, 7, 16)))
        self.assertEqual(Run.objects.count(), 0)

    def test_no_late_runs_after_window(self):
        services.auto_run(ist(MONDAY, 12, 0))
        self.assertEqual(Run.objects.count(), 0)

    def test_disabled_or_manual_modes_never_auto_run(self):
        Mode.objects.filter(pk=self.bod.pk).update(enabled=False)
        Mode.objects.filter(pk=self.eod.pk).update(auto_run_time=None)
        services.auto_run(ist(MONDAY, 7, 16))
        services.auto_run(ist(MONDAY, 15, 41))
        self.assertEqual(Run.objects.count(), 0)

    def test_job_never_raises(self):
        with mock.patch.object(services, "finalize_stale", side_effect=RuntimeError("db gone")):
            self.assertEqual(services.auto_run(ist(MONDAY, 7, 16)), "error")

    def test_schedule_for(self):
        nxt = services.schedule_for(self.bod, ist(date(2026, 10, 31), 12))  # Saturday
        self.assertEqual(nxt, ist(MONDAY, 7, 15))


# ------------------------------------------------------------------ CSV
class CsvTests(TestCase):
    def test_parse_formats_and_errors(self):
        data = ("Date,Exchange,Description\n2026-01-26,NSE,Republic Day\n03-Mar-2026,,Holi\n"
                "31/03/2026,BSE,Mahavir Jayanti\nbad,NSE,x\n2026-04-03,XYZ,Good Friday\n2026-04-14,NSE,\n").encode()
        out = services.parse_holidays_csv(data, default_exchange="NSE")
        self.assertEqual(out.rows, [("NSE", date(2026, 1, 26), "Republic Day"), ("NSE", date(2026, 3, 3), "Holi"),
                                    ("BSE", date(2026, 3, 31), "Mahavir Jayanti")])
        self.assertEqual(len(out.errors), 3)

    def test_header_required(self):
        out = services.parse_holidays_csv(b"when,what\n2026-01-01,x\n")
        self.assertFalse(out.rows)
        self.assertIn("Header", out.errors[0])
        self.assertIn("empty", services.parse_holidays_csv(b"").errors[0])

    def test_import_upserts(self):
        Holiday.objects.create(exchange="NSE", date=date(2026, 1, 26), description="old")
        created, updated = services.import_holidays([("NSE", date(2026, 1, 26), "Republic Day"), ("ALL", date(2026, 1, 26), "All")])
        self.assertEqual((created, updated), (1, 1))
        self.assertEqual(Holiday.objects.get(exchange="NSE").description, "Republic Day")


# ------------------------------------------------------------------ views and permissions
class ViewTests(TestCase):
    def setUp(self):
        self.viewer, self.operator, self.admin = users()
        self.mode = make_mode()
        url_check("Portal")
        self.item = ChecklistItem.objects.create(mode=self.mode, name="Portal up", ref_name="Portal")
        self.manual = ChecklistItem.objects.create(mode=self.mode, name="Feed", kind="manual", order=20,
                                                   instructions="Check the feed")

    def test_pages_render_for_viewer(self):
        run = services.start_run(self.mode)
        Holiday.objects.create(exchange="NSE", date=date(2026, 1, 26), description="Republic Day", source="example")
        c = client_for(self.viewer)
        for name, args in [("bodeod:status", []), ("bodeod:keys", []), ("bodeod:history", []), ("bodeod:detail", [run.pk]),
                           ("bodeod:checklist", []), ("bodeod:holidays", [])]:
            r = c.get(reverse(name, args=args))
            self.assertEqual(r.status_code, 200, name)
            self.assertNotContains(r, "Run now")  # viewers get no mutation buttons
            self.assertNotContains(r, "Sign off")
        self.assertContains(c.get(reverse("bodeod:holidays") + "?year=2026"), "Republic Day")
        self.assertContains(c.get(reverse("bodeod:keys") + "?mode=BOD&kind=manual"), "Feed")

    def test_empty_state(self):
        Mode.objects.all().delete()
        r = client_for(self.admin).get(reverse("bodeod:status"))
        self.assertContains(r, "No BOD / EOD modes configured")
        self.assertContains(r, "seed_bodeod")

    def test_status_and_keys_show_codes(self):
        services.start_run(self.mode)
        r = client_for(self.operator).get(reverse("bodeod:status"))
        self.assertContains(r, "Run now")
        self.assertContains(r, "PENDING")
        r = client_for(self.operator).get(reverse("bodeod:keys"))
        self.assertContains(r, "Sign off")

    def test_viewer_cannot_run(self):
        r = client_for(self.viewer).post(reverse("bodeod:run", args=[self.mode.pk]))
        self.assertEqual(r.status_code, 302)
        self.assertEqual(Run.objects.count(), 0)

    def test_get_on_mutation_is_rejected(self):
        self.assertEqual(client_for(self.operator).get(reverse("bodeod:run", args=[self.mode.pk])).status_code, 405)

    def test_csrf_enforced(self):
        c = Client(enforce_csrf_checks=True)
        c.force_login(self.operator)
        self.assertEqual(c.post(reverse("bodeod:run", args=[self.mode.pk])).status_code, 403)
        self.assertEqual(Run.objects.count(), 0)

    def test_operator_runs_with_audit(self):
        with mock.patch("probes.runner.run_url_checks") as urls:
            r = client_for(self.operator).post(reverse("bodeod:run", args=[self.mode.pk]), {"refresh": "1"})
        run = Run.objects.get()
        self.assertRedirects(r, run.get_absolute_url(), fetch_redirect_response=False)
        urls.assert_called_once()
        self.assertEqual(run.triggered_by, self.operator)
        a = AuditEvent.objects.get(action="run")
        self.assertEqual((a.actor, a.object_id, a.details["mode"]), (self.operator, str(run.pk), "BOD"))

    def test_run_without_refresh(self):
        with mock.patch("probes.runner.run_url_checks") as urls:
            client_for(self.operator).post(reverse("bodeod:run", args=[self.mode.pk]), {"refresh": "0"})
        urls.assert_not_called()
        self.assertFalse(Run.objects.get().refreshed)

    def test_run_refused_for_disabled_mode(self):
        Mode.objects.filter(pk=self.mode.pk).update(enabled=False)
        client_for(self.operator).post(reverse("bodeod:run", args=[self.mode.pk]))
        self.assertEqual(Run.objects.count(), 0)

    def test_sign_off_view(self):
        run = services.start_run(self.mode)
        res = run.results.get(name="Feed")
        url = reverse("bodeod:signoff", args=[res.pk])
        client_for(self.viewer).post(url, {"note": "x"})
        res.refresh_from_db()
        self.assertEqual(res.status, "pending")
        client_for(self.operator).post(url, {"note": ""})
        res.refresh_from_db()
        self.assertEqual(res.status, "pending")
        r = client_for(self.operator).post(url, {"note": "Feed is live", "next": reverse("bodeod:keys")})
        self.assertRedirects(r, reverse("bodeod:keys"), fetch_redirect_response=False)
        res.refresh_from_db()
        self.assertEqual((res.status, res.note), ("signed_off", "Feed is live"))
        self.assertTrue(AuditEvent.objects.filter(action="sign_off", object_id=str(res.pk)).exists())

    def test_unsafe_next_is_ignored(self):
        run = services.start_run(self.mode)
        res = run.results.get(name="Feed")
        r = client_for(self.operator).post(reverse("bodeod:signoff", args=[res.pk]), {"note": "ok", "next": "https://evil.example/"})
        self.assertEqual(r["Location"], run.get_absolute_url())

    def test_revalidate_view(self):
        run = services.start_run(self.mode)
        with mock.patch("probes.runner.run_url_checks"):
            r = client_for(self.operator).post(reverse("bodeod:revalidate", args=[run.pk]))
        self.assertEqual(r.status_code, 302)
        self.assertTrue(AuditEvent.objects.filter(action="revalidate").exists())
        client_for(self.viewer).post(reverse("bodeod:revalidate", args=[run.pk]))
        self.assertEqual(AuditEvent.objects.filter(action="revalidate").count(), 1)

    def test_history_filters_and_export(self):
        services.start_run(self.mode)
        eod = make_mode("EOD", window_start=time(15, 30), window_end=time(16, 0), auto_run_time=None)
        ChecklistItem.objects.create(mode=eod, name="p", ref_name="Portal")
        services.start_run(eod)
        c = client_for(self.viewer)
        r = c.get(reverse("bodeod:history") + "?mode=EOD")
        self.assertEqual(r.context["page"].paginator.count, 1)
        r = c.get(reverse("bodeod:history") + "?status=pass")
        self.assertEqual(r.context["page"].paginator.count, 1)
        r = c.get(reverse("bodeod:history") + "?q=Portal")
        self.assertEqual(r.context["page"].paginator.count, 2)
        self.assertEqual([p.n_total for p in r.context["page"]], [1, 2])  # search must not distort counts
        r = c.get(reverse("bodeod:history") + "?from=2000-01-01&to=2000-01-02")
        self.assertEqual(r.context["page"].paginator.count, 0)
        r = c.get(reverse("bodeod:history_export"))
        self.assertEqual(r["Content-Type"], "text/csv")
        self.assertEqual(len(r.content.decode().strip().splitlines()), 3)

    def test_api_status(self):
        services.start_run(self.mode)
        d = client_for(self.viewer).get(reverse("bodeod:api_status")).json()
        self.assertEqual(d["modes"][0]["code"], "BOD")
        self.assertEqual(len(d["modes"][0]["latest_run"]["items"]), 2)

    # checklist editor
    def test_checklist_editor_is_admin_only(self):
        data = {"mode": self.mode.pk, "order": 30, "name": "New item", "kind": "domain", "ref_name": "nse.example.com",
                "critical": "on", "enabled": "on", "instructions": ""}
        client_for(self.operator).post(reverse("bodeod:checklist"), data)
        self.assertFalse(ChecklistItem.objects.filter(name="New item").exists())
        r = client_for(self.admin).post(reverse("bodeod:checklist"), data)
        self.assertEqual(r.status_code, 302)
        item = ChecklistItem.objects.get(name="New item")
        self.assertTrue(AuditEvent.objects.filter(action="create", object_id=str(item.pk)).exists())

    def test_checklist_validation(self):
        r = client_for(self.admin).post(reverse("bodeod:checklist"), {"mode": self.mode.pk, "order": 30, "name": "X",
                                                                        "kind": "url_check", "ref_name": ""})
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Name the URL check")
        r = client_for(self.admin).post(reverse("bodeod:checklist"), {"mode": self.mode.pk, "order": 30, "name": "Feed",
                                                                        "kind": "manual"})
        self.assertContains(r, "already has an item")

    def test_edit_move_delete_item(self):
        c = client_for(self.admin)
        c.post(reverse("bodeod:checklist"), {"pk": self.item.pk, "mode": self.mode.pk, "order": 10, "name": "Portal reachable",
                                             "kind": "url_check", "ref_name": "Portal", "enabled": "on"})
        self.item.refresh_from_db()
        self.assertEqual((self.item.name, self.item.critical), ("Portal reachable", False))
        c.post(reverse("bodeod:item_move", args=[self.manual.pk]), {"direction": "up"})
        self.assertEqual(list(self.mode.items.order_by("order").values_list("name", flat=True)), ["Feed", "Portal reachable"])
        client_for(self.operator).post(reverse("bodeod:item_delete", args=[self.item.pk]))
        self.assertTrue(ChecklistItem.objects.filter(pk=self.item.pk).exists())
        c.post(reverse("bodeod:item_delete", args=[self.item.pk]))
        self.assertFalse(ChecklistItem.objects.filter(pk=self.item.pk).exists())
        self.assertTrue(AuditEvent.objects.filter(action="delete", object_type="bodeod.checklistitem").exists())

    def test_mode_save(self):
        c = client_for(self.admin)
        r = c.post(reverse("bodeod:mode_save"), {"code": "EOD", "name": "End of Day", "site": "All Sites", "window_start": "15:30",
                                                 "window_end": "16:00", "auto_run_time": "15:40", "refresh_checks": "on", "enabled": "on"})
        self.assertEqual(r.status_code, 302)
        self.assertTrue(Mode.objects.filter(code="EOD").exists())
        r = c.post(reverse("bodeod:mode_save"), {"code": "ADP", "name": "ADP", "site": "All Sites", "window_start": "16:00",
                                                 "window_end": "15:00", "auto_run_time": "17:00"})
        self.assertEqual(r.status_code, 400)
        self.assertFalse(Mode.objects.filter(code="ADP").exists())
        r = c.post(reverse("bodeod:mode_save"), {"code": "BOD", "name": "dup", "site": "All Sites", "window_start": "07:00",
                                                 "window_end": "09:00"})
        self.assertEqual(r.status_code, 400)
        c.post(reverse("bodeod:mode_save"), {"pk": self.mode.pk, "code": "BOD", "name": "BOD renamed", "site": "All Sites",
                                             "window_start": "07:00", "window_end": "09:00", "auto_run_time": "07:30"})
        self.mode.refresh_from_db()
        self.assertEqual((self.mode.name, self.mode.auto_run_time, self.mode.enabled), ("BOD renamed", time(7, 30), False))
        client_for(self.operator).post(reverse("bodeod:mode_save"), {"pk": self.mode.pk, "code": "BOD", "name": "hacked",
                                                                    "site": "All Sites", "window_start": "07:00", "window_end": "09:00"})
        self.mode.refresh_from_db()
        self.assertEqual(self.mode.name, "BOD renamed")

    # holidays
    def test_holiday_add_permissions(self):
        data = {"date": "2026-12-25", "exchange": "NSE", "description": "Christmas"}
        client_for(self.viewer).post(reverse("bodeod:holidays"), data)
        self.assertFalse(Holiday.objects.exists())
        r = client_for(self.operator).post(reverse("bodeod:holidays"), data)
        self.assertEqual(r.status_code, 302)
        h = Holiday.objects.get()
        self.assertEqual(h.source, "manual")
        self.assertTrue(AuditEvent.objects.filter(action="create", object_type="bodeod.holiday").exists())
        r = client_for(self.operator).post(reverse("bodeod:holidays"), data)
        self.assertEqual(r.status_code, 400)

    def test_holiday_upload(self):
        f = SimpleUploadedFile("nse.csv", b"date,description\n26-Jan-2026,Republic Day\n2026-03-03,Holi\nnope,x\n", "text/csv")
        r = client_for(self.operator).post(reverse("bodeod:holiday_upload"), {"file": f, "default_exchange": "NSE"})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(Holiday.objects.filter(exchange="NSE").count(), 2)
        self.assertEqual(AuditEvent.objects.get(action="import").details["created"], 2)
        f = SimpleUploadedFile("x.csv", b"date,description\n2026-01-01,x\n", "text/csv")
        client_for(self.viewer).post(reverse("bodeod:holiday_upload"), {"file": f, "default_exchange": "NSE"})
        self.assertEqual(Holiday.objects.count(), 2)
        f = SimpleUploadedFile("x.exe", b"MZ", "application/octet-stream")
        client_for(self.operator).post(reverse("bodeod:holiday_upload"), {"file": f, "default_exchange": "NSE"})
        self.assertEqual(Holiday.objects.count(), 2)

    def test_holiday_delete_admin_only_and_export(self):
        h = Holiday.objects.create(exchange="NSE", date=date(2026, 1, 26), description="Republic Day")
        client_for(self.operator).post(reverse("bodeod:holiday_delete", args=[h.pk]))
        self.assertTrue(Holiday.objects.filter(pk=h.pk).exists())
        r = client_for(self.admin).get(reverse("bodeod:holidays_export") + "?year=2026")
        self.assertIn("2026-01-26,NSE,Republic Day", r.content.decode())
        client_for(self.admin).post(reverse("bodeod:holiday_delete", args=[h.pk]))
        self.assertFalse(Holiday.objects.filter(pk=h.pk).exists())
        self.assertTrue(AuditEvent.objects.filter(action="delete", object_type="bodeod.holiday").exists())


class SiteScopeTests(TestCase):
    def test_site_member_sees_only_own_and_global_modes(self):
        from core.models import Site
        mumbai = Site.objects.create(name="Mumbai", code="mumbai")
        Site.objects.create(name="Delhi", code="delhi")
        make_mode("BOD", site="Mumbai")
        make_mode("EOD", site="Delhi", window_start=time(15, 30), window_end=time(16, 0), auto_run_time=None)
        make_mode("ADP", window_start=time(16, 0), window_end=time(20, 0), auto_run_time=None)
        u = User.objects.create_user("m")
        Membership.objects.create(user=u, site=mumbai, role="operator")
        r = client_for(u).get(reverse("bodeod:status"))
        codes = [c["mode"].code for c in r.context["cards"]]
        self.assertEqual(sorted(codes), ["ADP", "BOD"])
        delhi_mode = Mode.objects.get(code="EOD")
        self.assertEqual(client_for(u).post(reverse("bodeod:run", args=[delhi_mode.pk])).status_code, 404)


class SeedTests(TestCase):
    def test_seed_is_idempotent_and_marked(self):
        call_command("seed_bodeod", stdout=mock.MagicMock())
        call_command("seed_bodeod", stdout=mock.MagicMock())
        self.assertEqual(Mode.objects.count(), 3)
        self.assertEqual(Holiday.objects.filter(source="example", date__year=2026).count(), 15)
        self.assertFalse(ChecklistItem.objects.exclude(instructions__startswith="Example").exists())
        self.assertTrue(ChecklistItem.objects.filter(kind="url_check", ref_name="NSE Web Portal").exists())
        self.assertFalse(Run.objects.exists())  # never fabricates results
        call_command("seed_bodeod", "--remove", stdout=mock.MagicMock())
        self.assertFalse(Holiday.objects.exists())
        self.assertFalse(ChecklistItem.objects.exists())
