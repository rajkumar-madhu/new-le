import io
from datetime import timedelta
from unittest import mock

from django.apps import apps
from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from core import prometheus
from core.events import emit
from core.models import AuditEvent, Event, Membership, Site
from domainmonitor.models import Domain, DomainCheck
from urlchecker.models import UrlCheck, UrlResult

from . import heatmap as hm
from . import jobs, services, topology
from .listeners import impact_for_event
from .models import ConfigurationItem, License, Relationship, Software


def _has_model(app_label, model):
    """True when the other module is present with the model (main may carry an empty stub app)."""
    try:
        apps.get_model(app_label, model)
        return True
    except LookupError:
        return False

T = "default"


def ci(name, ci_type="server", **kw):
    kw.setdefault("tenant_key", T)
    return ConfigurationItem.objects.create(name=name, ci_type=ci_type, **kw)


def rel(s, t, rt="depends_on", **kw):
    return Relationship.objects.create(source=s, target=t, rel_type=rt, **kw)


@override_settings(LINKEDEYE_TENANT=T)
class ModelTests(TestCase):
    def test_license_usage_and_states(self):
        sw = Software.objects.create(tenant_key=T, name="RHEL", version="9")
        hosts = [ci(f"h{i}") for i in range(3)]
        sw.installs.set(hosts)
        lic = License.objects.create(tenant_key=T, product="RHEL sub", software=sw, seats=2)
        self.assertEqual(lic.used, 3)
        self.assertTrue(lic.over_allocated)
        self.assertEqual(lic.state, "over")
        lic.seats = 5
        lic.expiry = timezone.localdate() + timedelta(days=10)
        self.assertEqual(lic.state, "expiring")
        lic.expiry = timezone.localdate() - timedelta(days=1)
        self.assertEqual(lic.state, "expired")
        lic2 = License.objects.create(tenant_key=T, product="Unlinked", seats=1)
        self.assertEqual((lic2.used, lic2.state), (0, "ok"))

    def test_ci_days_and_flags(self):
        c = ci("srv", warranty_end=timezone.localdate() + timedelta(days=5), attributes={"example": True})
        self.assertEqual(c.warranty_days, 5)
        self.assertIsNone(c.eol_days)
        self.assertTrue(c.is_hardware and c.is_example)
        self.assertEqual(c.get_absolute_url(), reverse("cmdb:item_detail", args=[c.pk]))

    def test_relationship_rejects_self_link(self):
        from django.core.exceptions import ValidationError
        a = ci("a")
        with self.assertRaises(ValidationError):
            Relationship(source=a, target=a, rel_type="depends_on").full_clean()


@override_settings(LINKEDEYE_TENANT=T)
class ServiceTests(TestCase):
    def setUp(self):
        self.dom = ci("Trading", "business_domain")
        self.db = ci("PostgreSQL", "database", business_domain="Trading")
        self.host = ci("prod-db-01", "server")
        self.oms = ci("OMS", "application", business_domain="Trading")
        self.risk = ci("Risk Engine", "application")
        rel(self.db, self.host, "hosted_on")
        rel(self.oms, self.db, "depends_on")
        rel(self.risk, self.oms, "depends_on")
        rel(self.risk, self.dom, "part_of")
        rel(self.oms, self.dom, "part_of")

    def test_find_ci(self):
        self.assertEqual(services.find_ci("oms"), self.oms)
        self.assertEqual(services.find_ci(" OMS "), self.oms)
        self.assertIsNone(services.find_ci("missing"))
        self.assertIsNone(services.find_ci(""))
        ci("OMS", "application", tenant_key="other")
        self.assertEqual(services.find_ci("OMS"), self.oms)

    def test_impact_is_transitive_and_follows_part_of(self):
        rows = services.impacted(self.host)
        names = [(r["ci"].name, r["depth"]) for r in rows]
        self.assertEqual(names[:2], [("PostgreSQL", 1), ("OMS", 2)])
        self.assertIn(("Risk Engine", 3), names)
        self.assertIn(("Trading", 3), names)       # OMS part_of Trading
        oms_row = next(r for r in rows if r["ci"] == self.oms)
        self.assertEqual(oms_row["via_text"], "depends on PostgreSQL")
        dom_row = next(r for r in rows if r["ci"] == self.dom)
        self.assertTrue(dom_row["via_text"].startswith("contains"))
        self.assertEqual(services.impacted(self.risk), [r for r in services.impacted(self.risk)])
        self.assertEqual([r["ci"].name for r in services.impacted(self.risk)], ["Trading"])

    def test_dependencies_and_cycles(self):
        deps = [c.name for c, _d in services.dependencies(self.risk)]
        self.assertEqual(set(deps), {"OMS", "PostgreSQL", "prod-db-01"})
        self.assertTrue(services.would_cycle(self.host, self.risk, "depends_on"))
        self.assertFalse(services.would_cycle(self.risk, self.host, "depends_on"))
        self.assertFalse(services.would_cycle(self.host, self.risk, "connects_to"))
        rel(self.host, self.risk, "connects_to")     # non-dependency loop does not break traversal
        self.assertEqual(len(services.impacted(self.host)), 4)

    def test_domains(self):
        ci("Payments API", "service", business_domain="Payments")
        self.assertEqual(services.domain_names(), ["Payments", "Trading"])
        dom_ci, members = services.domain_members("Trading")
        self.assertEqual(dom_ci, self.dom)
        self.assertEqual({m.name for m in members}, {"PostgreSQL", "OMS", "Risk Engine"})

    def test_link_health(self):
        good = UrlCheck.objects.create(tenant_key=T, name="ok", url="https://a.example/", last_status="online")
        bad = UrlCheck.objects.create(tenant_key=T, name="bad", url="https://b.example/", last_status="down")
        self.oms.url_checks.add(good)
        self.risk.url_checks.add(good, bad)
        d = Domain.objects.create(tenant_key=T, site_key="All Sites", hostname="x.example.com", status="up", ssl_status="Expiring")
        self.db.domains.add(d)
        h = services.link_health([self.oms, self.risk, self.db, self.host])
        self.assertEqual(h, {self.oms.pk: "healthy", self.risk.pk: "critical", self.db.pk: "warning", self.host.pk: "unknown"})

    def test_recent_incidents_via_servicedesk(self):
        if not _has_model("servicedesk", "Ticket"):
            self.skipTest("servicedesk not installed")
        from servicedesk.models import Ticket
        check = UrlCheck.objects.create(tenant_key=T, name="oms-url", url="https://oms.example/")
        self.oms.url_checks.add(check)
        Ticket.objects.create(tenant_key=T, kind="incident", title="OMS slow", ci_name="OMS", priority="P1")
        Ticket.objects.create(tenant_key=T, kind="incident", title="URL down", fingerprint=f"url:{check.pk}")
        Ticket.objects.create(tenant_key=T, kind="incident", title="Other", ci_name="Other")
        res = services.recent_incidents(["OMS"], fingerprints=services.ci_fingerprints([self.oms]))
        self.assertEqual({i["title"] for i in res["items"]}, {"OMS slow", "URL down"})
        self.assertEqual(res["open"], 2)
        self.assertTrue(res["items"][0]["number"])

    def test_recent_incidents_without_servicedesk(self):
        with mock.patch("cmdb.services.apps.get_model", side_effect=LookupError):
            self.assertIsNone(services.recent_incidents(["OMS"]))

    def test_can_manage_site_scoping(self):
        site = Site.objects.create(name="Mumbai (NSE)", code="mum")
        op = User.objects.create_user("op")
        Membership.objects.create(user=op, site=site, role="operator")
        self.assertTrue(services.can_manage(op, "operate", "Mumbai (NSE)"))
        self.assertFalse(services.can_manage(op, "operate", "DR Site"))
        self.assertFalse(services.can_manage(op, "operate", "All Sites"))
        staff = User.objects.create_user("staff", is_staff=True)
        self.assertTrue(services.can_manage(staff, "operate", "All Sites"))
        self.assertFalse(services.can_manage(staff, "admin", "All Sites"))


@override_settings(LINKEDEYE_TENANT=T, PROMETHEUS_URL="")
class HeatmapTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_superuser("root", "r@example.com", "pw")
        self.dom = ci("Trading", "business_domain", description="Trading systems")
        self.oms = ci("OMS", "application", business_domain="Trading")
        self.md = ci("Market Data", "service", business_domain="Trading")
        self.host = ci("prod-oms-01", "server", prometheus_instance="prod-oms-01:9100")
        rel(self.oms, self.host, "runs_on")
        rel(self.oms, self.md, "depends_on")
        self.check = UrlCheck.objects.create(tenant_key=T, name="OMS URL", url="https://oms.example/", degraded_ms=1000)
        self.oms.url_checks.add(self.check)
        now = timezone.now()
        # 20 samples: 19 up (100..1900 ms), 1 down with no HTTP answer
        for i in range(19):
            UrlResult.objects.create(url_check=self.check, checked_at=now - timedelta(minutes=i + 1), status="online",
                                     http_status=200, response_ms=100.0 * (i + 1))
        UrlResult.objects.create(url_check=self.check, checked_at=now - timedelta(minutes=30), status="down")
        UrlResult.objects.create(url_check=self.check, checked_at=now - timedelta(hours=3), status="down")  # outside 1h

    def test_grade(self):
        self.assertEqual(hm.grade("availability", 99.9), "healthy")
        self.assertEqual(hm.grade("availability", 98), "warning")
        self.assertEqual(hm.grade("availability", 90), "critical")
        self.assertEqual(hm.grade("latency", 1400, 1000), "healthy")
        self.assertEqual(hm.grade("latency", 2000, 1000), "warning")
        self.assertEqual(hm.grade("cpu", 95), "critical")
        self.assertEqual(hm.grade("cpu", None), "unknown")

    def test_build_probe_metrics(self):
        d = hm.build(self.user, window="1h")
        trading = next(x for x in d["domains"] if x["name"] == "Trading")
        oms = next(r for r in trading["service_rows"] if r["name"] == "OMS")
        m = oms["metrics"]
        self.assertAlmostEqual(m["availability"], 95.0)
        self.assertAlmostEqual(m["errors"], 5.0)
        self.assertAlmostEqual(m["response"], 1000.0)
        self.assertEqual(m["latency"], 1900.0)
        states = {c["col"]: c["state"] for c in oms["cells"]}
        self.assertEqual(states["availability"], "critical")
        self.assertEqual(states["errors"], "warning")     # 5 % is the warning limit
        self.assertEqual(states["response"], "healthy")
        self.assertEqual(states["latency"], "warning")
        self.assertEqual(states["cpu"], "unknown")   # Prometheus not configured
        md = next(r for r in trading["service_rows"] if r["name"] == "Market Data")
        self.assertTrue(all(c["state"] == "unknown" for c in md["cells"]))
        self.assertEqual(trading["health"], "critical")
        self.assertEqual(d["counts"]["critical"], 1)
        # 7-day window includes the older failure
        d7 = hm.build(self.user, window="7d")
        oms7 = next(r for x in d7["domains"] for r in x["service_rows"] if r["name"] == "OMS")
        self.assertAlmostEqual(oms7["metrics"]["availability"], 100 * 19 / 21)

    def test_domain_checks_count(self):
        dom = Domain.objects.create(tenant_key=T, site_key="All Sites", hostname="md.example.com")
        self.md.domains.add(dom)
        DomainCheck.objects.create(domain=dom, checked_at=timezone.now(), up=True, http_status=200, response_ms=80,
                                   dns_status="Resolved", ssl_status="Valid")
        d = hm.build(self.user)
        md = next(r for x in d["domains"] for r in x["service_rows"] if r["name"] == "Market Data")
        self.assertEqual(md["metrics"]["availability"], 100.0)

    def test_filters(self):
        d = hm.build(self.user, service="OMS")
        self.assertEqual([s["name"] for g in d["rows"] for s in g["services"]], ["OMS"])
        d = hm.build(self.user, host=str(self.host.pk))
        self.assertEqual([s["name"] for g in d["rows"] for s in g["services"]], ["OMS"])
        d = hm.build(self.user, domain="nope")
        self.assertEqual(d["rows"], [])

    @override_settings(PROMETHEUS_URL="http://prom.example:9090")
    def test_prometheus_host_metrics(self):
        from django.core.cache import cache
        cache.clear()
        values = {"cpu": 91.0, "memory": 50.0, "disk": 85.0, "network": 0.0}

        def fake_query(promql):
            col = next(k for k, tpl in hm.PROMQL.items() if tpl.split("{")[0][:20] in promql)
            self.assertIn("prod-oms-01:9100", promql)
            return [{"metric": {"instance": "prod-oms-01:9100"}, "value": values[col]}]
        with mock.patch.object(prometheus, "query", side_effect=fake_query) as q:
            d = hm.build(self.user)
        self.assertEqual(q.call_count, 4)
        oms = next(r for x in d["domains"] for r in x["service_rows"] if r["name"] == "OMS")
        states = {c["col"]: c["state"] for c in oms["cells"]}
        self.assertEqual((states["cpu"], states["memory"], states["disk"], states["network"]),
                         ("critical", "healthy", "warning", "healthy"))
        self.assertEqual(oms["instances"], ["prod-oms-01:9100"])

    @override_settings(PROMETHEUS_URL="http://prom.example:9090")
    def test_prometheus_error_is_reported(self):
        from django.core.cache import cache
        cache.clear()
        with mock.patch.object(prometheus, "query", side_effect=prometheus.PrometheusError("Prometheus unreachable: refused")):
            d = hm.build(self.user)
        self.assertIn("unreachable", d["prometheus_error"])
        oms = next(r for x in d["domains"] for r in x["service_rows"] if r["name"] == "OMS")
        self.assertEqual({c["state"] for c in oms["cells"] if c["col"] == "cpu"}, {"unknown"})

    def test_promql_regex_escapes(self):
        self.assertEqual(hm.promql_regex({"a.b:9100"}), "a\\\\.b:9100")

    def test_domain_chain(self):
        d = hm.build(self.user)
        trading = next(x for x in d["domains"] if x["name"] == "Trading")
        chain = hm.domain_chain(trading, d["edges"], d["ci_map"], hm.health_from_rows(d["domains"]))
        self.assertEqual([n["name"] for n in chain][-1], "OMS")


@override_settings(LINKEDEYE_TENANT=T)
class TopologyTests(TestCase):
    def test_layered_layout(self):
        dom = ci("Trading", "business_domain")
        svc = ci("OMS", "application")
        host = ci("h1", "server")
        rel(svc, host, "runs_on")
        rel(svc, dom, "part_of")
        edges = services.edges_for()
        g = topology.layout([dom, svc, host], edges, {svc.pk: "critical"}, root_id=svc.pk)
        y = {n["ci"].name: n["y"] for n in g["nodes"]}
        self.assertLess(y["Trading"], y["OMS"])
        self.assertLess(y["OMS"], y["h1"])
        self.assertEqual(len(g["edges"]), 2)
        self.assertTrue(all(e["path"].startswith("M") for e in g["edges"]))
        node = next(n for n in g["nodes"] if n["ci"] == svc)
        self.assertEqual((node["cls"], node["root"]), ("crit", True))
        self.assertEqual(topology.neighbourhood(host.pk, edges), {host.pk, svc.pk, dom.pk})

    def test_wide_layers_wrap(self):
        cis = [ci(f"srv-{i:02d}") for i in range(topology.MAX_PER_ROW + 3)]
        g = topology.layout(cis, [], {})
        self.assertEqual(len({n["y"] for n in g["nodes"]}), 2)


@override_settings(LINKEDEYE_TENANT=T)
class ViewTests(TestCase):
    def setUp(self):
        self.viewer = User.objects.create_user("viewer", password="pw")
        self.operator = User.objects.create_user("operator", password="pw", is_staff=True)
        self.admin = User.objects.create_superuser("admin", "a@example.com", "pw")
        self.srv = ci("prod-oms-01", "server", ip_address="10.0.0.1", vendor="Dell", warranty_end=timezone.localdate() + timedelta(days=20))
        self.svc = ci("OMS", "application", business_domain="Trading")
        self.dom = ci("Trading", "business_domain")
        rel(self.svc, self.srv, "runs_on")
        self.sw = Software.objects.create(tenant_key=T, name="RHEL", version="9")
        self.sw.installs.add(self.srv)
        self.lic = License.objects.create(tenant_key=T, product="RHEL sub", software=self.sw, seats=1,
                                          expiry=timezone.localdate() + timedelta(days=30))

    def login(self, user):
        self.client.force_login(user)

    def test_pages_render_for_viewer(self):
        self.login(self.viewer)
        urls = [reverse(n) for n in ("cmdb:assets", "cmdb:software", "cmdb:licenses", "cmdb:lifecycle", "cmdb:topology",
                                     "cmdb:items", "cmdb:relationships", "cmdb:heatmap")]
        urls += [reverse("cmdb:item_detail", args=[self.svc.pk]), reverse("cmdb:software_detail", args=[self.sw.pk]),
                 reverse("cmdb:topology") + f"?root={self.svc.pk}", reverse("cmdb:topology") + "?domain=Trading",
                 reverse("cmdb:heatmap") + "?domain=Trading&tab=services", reverse("cmdb:heatmap") + "?tab=incidents&window=7d",
                 reverse("cmdb:lifecycle") + "?window=overdue", reverse("cmdb:items") + "?q=oms&type=application"]
        for u in urls:
            r = self.client.get(u)
            self.assertEqual(r.status_code, 200, u)
        r = self.client.get(reverse("cmdb:heatmap"))
        self.assertContains(r, "OMS")
        self.assertContains(r, "not connected")       # Prometheus not configured
        self.assertNotContains(r, "Add Domain")
        r = self.client.get(reverse("cmdb:assets"))
        self.assertContains(r, "prod-oms-01")
        self.assertNotContains(r, "OMS</a>")          # services are not hardware assets
        r = self.client.get(reverse("cmdb:licenses"))
        self.assertContains(r, "Over-allocated")
        r = self.client.get(reverse("cmdb:item_detail", args=[self.srv.pk]))
        self.assertContains(r, "Impact Analysis")
        self.assertContains(r, "OMS")

    def test_empty_states(self):
        ConfigurationItem.objects.all().delete()
        self.login(self.viewer)
        self.assertContains(self.client.get(reverse("cmdb:heatmap")), "No services in the CMDB yet")
        self.assertContains(self.client.get(reverse("cmdb:topology")), "No configuration items with relationships yet")

    def test_viewer_cannot_mutate(self):
        self.login(self.viewer)
        self.assertEqual(self.client.get(reverse("cmdb:item_create")).status_code, 403)
        r = self.client.post(reverse("cmdb:item_create"), {"name": "x", "ci_type": "server", "status": "active",
                                                           "environment": "prod", "site": "All Sites"})
        self.assertEqual(r.status_code, 302)
        self.assertFalse(ConfigurationItem.objects.filter(name="x").exists())
        self.client.post(reverse("cmdb:item_delete", args=[self.srv.pk]))
        self.assertTrue(ConfigurationItem.objects.filter(pk=self.srv.pk).exists())
        self.client.post(reverse("cmdb:relationship_create"), {"source": self.srv.pk, "target": self.dom.pk, "rel_type": "part_of",
                                                               "origin": "manual", "confidence": 100})
        self.assertEqual(Relationship.objects.count(), 1)

    def test_operator_creates_and_edits_ci_with_audit_and_event(self):
        self.login(self.operator)
        r = self.client.post(reverse("cmdb:item_create"), {
            "name": "prod-db-01", "ci_type": "server", "status": "active", "environment": "prod", "site": "All Sites",
            "ip_address": "10.0.0.9", "purchase_date": "2024-01-01", "warranty_end": "2027-01-01", "attributes": '{"rack": "R1"}'})
        obj = ConfigurationItem.objects.get(name="prod-db-01")
        self.assertRedirects(r, obj.get_absolute_url())
        self.assertEqual((obj.tenant_key, obj.attributes), (T, {"rack": "R1"}))
        self.assertTrue(AuditEvent.objects.filter(action="create", object_type="cmdb.configurationitem", object_id=str(obj.pk)).exists())
        self.assertTrue(Event.objects.filter(source="cmdb", kind="ci_created").exists())
        r = self.client.post(reverse("cmdb:item_edit", args=[obj.pk]), {
            "name": "prod-db-01", "ci_type": "server", "status": "maintenance", "environment": "prod", "site": "All Sites"})
        self.assertEqual(r.status_code, 302)
        obj.refresh_from_db()
        self.assertEqual(obj.status, "maintenance")
        self.assertTrue(AuditEvent.objects.filter(action="update", object_id=str(obj.pk)).exists())
        self.assertTrue(Event.objects.filter(source="cmdb", kind="ci_status").exists())

    def test_form_validation(self):
        self.login(self.operator)
        r = self.client.post(reverse("cmdb:item_create"), {
            "name": "oms", "ci_type": "server", "status": "active", "environment": "prod", "site": "All Sites",
            "purchase_date": "2025-01-01", "warranty_end": "2024-01-01", "attributes": "[1, 2]"})
        self.assertEqual(r.status_code, 200)
        form = r.context["form"]
        self.assertIn("name", form.errors)          # case-insensitive duplicate
        self.assertIn("warranty_end", form.errors)
        self.assertIn("attributes", form.errors)

    def test_operator_cannot_delete_admin_can(self):
        self.login(self.operator)
        self.client.post(reverse("cmdb:item_delete", args=[self.srv.pk]))
        self.assertTrue(ConfigurationItem.objects.filter(pk=self.srv.pk).exists())
        self.login(self.admin)
        r = self.client.post(reverse("cmdb:item_delete", args=[self.srv.pk]))
        self.assertRedirects(r, reverse("cmdb:items"))
        self.assertFalse(ConfigurationItem.objects.filter(pk=self.srv.pk).exists())
        self.assertTrue(AuditEvent.objects.filter(action="delete", object_type="cmdb.configurationitem").exists())
        self.assertEqual(Relationship.objects.count(), 0)

    def test_delete_requires_post(self):
        self.login(self.admin)
        self.assertEqual(self.client.get(reverse("cmdb:item_delete", args=[self.srv.pk])).status_code, 405)

    def test_csrf_enforced(self):
        from django.test import Client
        c = Client(enforce_csrf_checks=True)
        c.force_login(self.admin)
        r = c.post(reverse("cmdb:item_delete", args=[self.srv.pk]))
        self.assertEqual(r.status_code, 403)
        self.assertTrue(ConfigurationItem.objects.filter(pk=self.srv.pk).exists())

    def test_site_scoping_hides_other_sites(self):
        mum = Site.objects.create(name="Mumbai (NSE)", code="mum")
        other = ci("dr-only", "server", site="DR Site")
        u = User.objects.create_user("scoped")
        Membership.objects.create(user=u, site=mum, role="operator")
        self.login(u)
        self.assertEqual(self.client.get(reverse("cmdb:item_detail", args=[other.pk])).status_code, 404)
        self.assertNotContains(self.client.get(reverse("cmdb:items")), "dr-only")
        # global records are visible but not editable for a site-scoped operator
        self.assertEqual(self.client.get(reverse("cmdb:item_detail", args=[self.srv.pk])).status_code, 200)
        self.assertEqual(self.client.get(reverse("cmdb:item_edit", args=[self.srv.pk])).status_code, 403)

    def test_relationship_create_duplicate_cycle_and_delete(self):
        self.login(self.operator)
        url = reverse("cmdb:relationship_create")
        r = self.client.post(url, {"source": self.svc.pk, "target": self.dom.pk, "rel_type": "part_of", "origin": "manual",
                                   "confidence": 100, "next": reverse("cmdb:item_detail", args=[self.svc.pk])})
        self.assertRedirects(r, reverse("cmdb:item_detail", args=[self.svc.pk]))
        self.assertTrue(Relationship.objects.filter(source=self.svc, target=self.dom, rel_type="part_of").exists())
        self.assertTrue(AuditEvent.objects.filter(action="create", object_type="cmdb.relationship").exists())
        self.client.post(url, {"source": self.svc.pk, "target": self.dom.pk, "rel_type": "part_of", "origin": "manual", "confidence": 100})
        self.assertEqual(Relationship.objects.filter(rel_type="part_of").count(), 1)
        # srv depends_on OMS would close a loop (OMS runs on srv)
        r = self.client.post(url, {"source": self.srv.pk, "target": self.svc.pk, "rel_type": "depends_on", "origin": "manual",
                                   "confidence": 100}, follow=True)
        self.assertContains(r, "dependency loop")
        self.assertFalse(Relationship.objects.filter(source=self.srv, target=self.svc).exists())
        r = self.client.post(url, {"source": self.srv.pk, "target": "https://evil.example/", "rel_type": "x"})
        self.assertEqual(r.status_code, 302)
        relobj = Relationship.objects.get(source=self.svc, rel_type="runs_on")
        self.client.post(reverse("cmdb:relationship_delete", args=[relobj.pk]))
        self.assertTrue(Relationship.objects.filter(pk=relobj.pk).exists())
        self.login(self.admin)
        self.client.post(reverse("cmdb:relationship_delete", args=[relobj.pk]))
        self.assertFalse(Relationship.objects.filter(pk=relobj.pk).exists())

    def test_open_redirect_is_ignored(self):
        self.login(self.operator)
        r = self.client.post(reverse("cmdb:relationship_create"), {"source": self.svc.pk, "target": self.dom.pk,
                                                                   "rel_type": "part_of", "next": "https://evil.example/"})
        self.assertEqual(r["Location"], reverse("cmdb:relationships"))

    def test_csv_export_and_import(self):
        self.login(self.operator)
        self.srv.description = "=HYPERLINK(evil)"
        self.srv.save()
        r = self.client.get(reverse("cmdb:assets_export"))
        body = r.content.decode()
        self.assertIn("prod-oms-01", body)
        self.assertNotIn("OMS,application", body)
        self.assertIn("'=HYPERLINK", body)
        csv_text = ("name,type,status,environment,site,ip_address,vendor,warranty_end,cost\n"
                    "prod-oms-01,server,active,prod,All Sites,10.0.0.1,HPE,2028-01-01,100\n"
                    "new-switch,Network Device,Active,Production,Mumbai (NSE),10.0.0.2,Cisco,,\n")
        r = self.client.post(reverse("cmdb:assets_import"), {"file": SimpleUploadedFile("a.csv", csv_text.encode()),
                                                             "update_existing": "on"})
        self.assertRedirects(r, reverse("cmdb:assets"))
        self.srv.refresh_from_db()
        self.assertEqual(self.srv.vendor, "HPE")
        self.assertEqual(ConfigurationItem.objects.get(name="new-switch").ci_type, "network_device")
        self.assertTrue(AuditEvent.objects.filter(action="import", details__created=1, details__updated=1).exists())

    def test_import_is_all_or_nothing(self):
        self.login(self.operator)
        csv_text = "name,type\ngood-one,server\nbad-one,spaceship\n"
        r = self.client.post(reverse("cmdb:items_import"), {"file": SimpleUploadedFile("a.csv", csv_text.encode())})
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "spaceship")
        self.assertFalse(ConfigurationItem.objects.filter(name="good-one").exists())
        r = self.client.post(reverse("cmdb:items_import"), {"file": SimpleUploadedFile("a.csv", b"foo,bar\n1,2\n")})
        self.assertContains(r, "must include a")
        self.assertEqual(self.client.get(reverse("cmdb:import_template")).status_code, 200)

    def test_software_and_license_crud(self):
        self.login(self.operator)
        r = self.client.post(reverse("cmdb:software_create"), {"name": "Nginx", "version": "1.26", "vendor": "F5",
                                                               "installs": [self.srv.pk, self.svc.pk]})
        sw = Software.objects.get(name="Nginx")
        self.assertRedirects(r, reverse("cmdb:software_detail", args=[sw.pk]))
        self.assertEqual(sw.installs.count(), 2)
        self.client.post(reverse("cmdb:software_installs", args=[sw.pk]), {"remove": self.svc.pk})
        self.assertEqual(list(sw.installs.all()), [self.srv])
        self.client.post(reverse("cmdb:software_installs", args=[sw.pk]), {"ci": self.svc.pk})
        self.assertEqual(sw.installs.count(), 2)
        r = self.client.post(reverse("cmdb:license_create"), {"product": "Nginx Plus", "software": sw.pk, "seats": 1}, follow=True)
        self.assertContains(r, "over-allocated")
        lic = License.objects.get(product="Nginx Plus")
        self.assertEqual(lic.used, 2)
        self.assertTrue(AuditEvent.objects.filter(object_type="cmdb.license", action="create").exists())
        # deletes are admin-only
        self.client.post(reverse("cmdb:license_delete", args=[lic.pk]))
        self.client.post(reverse("cmdb:software_delete", args=[sw.pk]))
        self.assertTrue(License.objects.filter(pk=lic.pk).exists() and Software.objects.filter(pk=sw.pk).exists())
        self.login(self.admin)
        self.client.post(reverse("cmdb:license_delete", args=[lic.pk]))
        self.client.post(reverse("cmdb:software_delete", args=[sw.pk]))
        self.assertFalse(License.objects.filter(pk=lic.pk).exists() or Software.objects.filter(pk=sw.pk).exists())

    def test_other_exports(self):
        self.login(self.viewer)
        for name in ("cmdb:items_export", "cmdb:software_export", "cmdb:licenses_export", "cmdb:lifecycle_export",
                     "cmdb:relationships_export"):
            r = self.client.get(reverse(name))
            self.assertEqual(r.status_code, 200, name)
            self.assertEqual(r["Content-Type"], "text/csv; charset=utf-8")
        self.assertIn("RHEL sub", self.client.get(reverse("cmdb:licenses_export")).content.decode())
        self.assertIn("Warranty end", self.client.get(reverse("cmdb:lifecycle_export")).content.decode())


@override_settings(LINKEDEYE_TENANT=T)
class JobAndListenerTests(TestCase):
    def test_lifecycle_scan_emits_once_per_transition(self):
        today = timezone.localdate()
        c = ci("old-server", warranty_end=today + timedelta(days=10))
        ci("ancient", warranty_end=today - timedelta(days=400))   # recorded silently
        sw = Software.objects.create(tenant_key=T, name="X")
        sw.installs.add(c)
        License.objects.create(tenant_key=T, product="X lic", software=sw, seats=0)
        jobs.lifecycle_scan()
        self.assertEqual(Event.objects.filter(source="cmdb", kind="lifecycle").count(), 1)
        self.assertEqual(Event.objects.filter(source="cmdb", kind="license").count(), 1)
        c.refresh_from_db()
        self.assertEqual(c.lifecycle_flag, "warranty_due")
        self.assertEqual(ConfigurationItem.objects.get(name="ancient").lifecycle_flag, "warranty_expired")
        jobs.lifecycle_scan()
        self.assertEqual(Event.objects.filter(source="cmdb").count(), 2)
        c.warranty_end = today + timedelta(days=700)
        c.save()
        jobs.lifecycle_scan()
        self.assertTrue(Event.objects.filter(source="cmdb", severity="ok", kind="lifecycle").exists())

    def test_lifecycle_scan_never_raises(self):
        with mock.patch("cmdb.jobs._scan", side_effect=RuntimeError("db gone")), self.assertLogs("linkedeye.cmdb", "ERROR"):
            self.assertEqual(jobs.lifecycle_scan(), "error")

    def test_job_registered(self):
        from core.jobs import JOBS
        self.assertIn("cmdb.lifecycle", JOBS)

    def test_impact_listener(self):
        host = ci("h1")
        svc = ci("OMS", "application")
        rel(svc, host, "runs_on")
        check = UrlCheck.objects.create(tenant_key=T, name="h1 health", url="https://h1.example/")
        host.url_checks.add(check)
        emit("urlchecker", "h1 health is Down", severity="critical", obj=check, fingerprint=f"url:{check.pk}")
        ev = Event.objects.get(source="cmdb", kind="impact")
        self.assertEqual(ev.severity, "info")
        self.assertEqual(ev.data["cis"], ["h1", "OMS"])
        # unrelated / non-critical events are ignored
        ok = Event.objects.create(source="urlchecker", title="fine", severity="ok", object_type="urlchecker.urlcheck",
                                  object_id=str(check.pk))
        self.assertIsNone(impact_for_event(ok))


@override_settings(LINKEDEYE_TENANT=T)
class SeedTests(TestCase):
    def test_seed_is_idempotent_links_checks_and_clears(self):
        UrlCheck.objects.create(tenant_key=T, name="NSE Web Portal", url="https://www.nseindia.com/")
        out = io.StringIO()
        call_command("seed_cmdb", stdout=out)
        n = ConfigurationItem.objects.count()
        self.assertGreater(n, 20)
        self.assertTrue(all(c.is_example and c.description.startswith("Example:") for c in ConfigurationItem.objects.all()))
        self.assertEqual(services.find_ci("Market Data").url_checks.get().name, "NSE Web Portal")
        self.assertTrue(License.objects.filter(software__isnull=False).exists())
        self.assertTrue(any(l.over_allocated for l in License.objects.all()))
        rels = Relationship.objects.count()
        call_command("seed_cmdb", stdout=out)
        self.assertEqual((ConfigurationItem.objects.count(), Relationship.objects.count()), (n, rels))
        user = User.objects.create_superuser("root", "r@example.com", "pw")
        self.client.force_login(user)
        self.assertEqual(self.client.get(reverse("cmdb:heatmap")).status_code, 200)
        self.assertEqual(self.client.get(reverse("cmdb:topology")).status_code, 200)
        call_command("seed_cmdb", "--clear", stdout=out)
        self.assertEqual((ConfigurationItem.objects.count(), Software.objects.count(), License.objects.count()), (0, 0, 0))


@override_settings(LINKEDEYE_TENANT=T, PROMETHEUS_URL="")
class RegressionTests(TestCase):
    """Bugs found by end-to-end testing."""

    def setUp(self):
        self.mum = Site.objects.create(name="Mumbai (NSE)", code="mum")
        self.siteop = User.objects.create_user("siteop")
        Membership.objects.create(user=self.siteop, site=self.mum, role="operator")
        self.admin = User.objects.create_superuser("admin", "a@example.com", "pw")
        self.viewer = User.objects.create_user("viewer")
        self.dr_host = ci("dr-oms-01", "server", site="DR Site", owner="Infra")
        self.dr_svc = ci("Reference Site", "service", site="DR Site")
        self.platform = ci("Platform", "business_domain", site="All Sites")
        self.mum_db = ci("PostgreSQL", "database", site="Mumbai (NSE)")
        rel(self.dr_svc, self.dr_host, "runs_on")
        rel(self.dr_svc, self.platform, "part_of")
        rel(self.mum_db, self.platform, "part_of")

    def _upload(self, text):
        return SimpleUploadedFile("cis.csv", text.encode(), content_type="text/csv")

    def test_import_cannot_take_over_item_on_other_site(self):
        self.client.force_login(self.siteop)
        r = self.client.post(reverse("cmdb:items_import"),
                             {"file": self._upload("name,site,owner\ndr-oms-01,Mumbai (NSE),pwned\n"), "update_existing": "on"})
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "a site you cannot manage")
        self.dr_host.refresh_from_db()
        self.assertEqual((self.dr_host.site, self.dr_host.owner), ("DR Site", "Infra"))
        self.assertTrue(AuditEvent.objects.filter(action="import", result="failed").exists())
        # the same user may still update items on their own site
        r = self.client.post(reverse("cmdb:items_import"),
                             {"file": self._upload("name,type,site,owner\nPostgreSQL,database,Mumbai (NSE),DBA\n"),
                              "update_existing": "on"})
        self.assertEqual(r.status_code, 302)
        self.mum_db.refresh_from_db()
        self.assertEqual(self.mum_db.owner, "DBA")

    def test_import_reports_unknown_choice_once(self):
        from . import csvio
        res = csvio.import_cis(self._upload("name,type\nX,toaster\n"), self.admin)
        self.assertEqual(len(res["errors"]), 1)
        self.assertIn("unknown type", res["errors"][0][1])
        self.assertNotIn("required", res["errors"][0][1])

    def test_detail_does_not_leak_items_from_other_sites(self):
        self.client.force_login(self.siteop)
        r = self.client.get(reverse("cmdb:item_detail", args=[self.platform.pk]))
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "PostgreSQL")
        self.assertNotContains(r, "Reference Site")
        self.assertNotContains(r, "dr-oms-01")
        # an unscoped admin still sees the whole graph
        self.client.force_login(self.admin)
        r = self.client.get(reverse("cmdb:item_detail", args=[self.platform.pk]))
        self.assertContains(r, "Reference Site")
        self.assertContains(r, "dr-oms-01")

    def test_recent_incidents_scoped_to_user_sites(self):
        if not _has_model("servicedesk", "Ticket"):
            self.skipTest("servicedesk not installed")
        from servicedesk.models import Ticket
        Ticket.objects.create(tenant_key=T, kind="incident", title="Mumbai DB slow", ci_name="PostgreSQL", site="Mumbai (NSE)")
        Ticket.objects.create(tenant_key=T, kind="incident", title="DR DB slow", ci_name="PostgreSQL", site="DR Site")
        mine = services.recent_incidents(["PostgreSQL"], user=self.siteop)
        self.assertEqual([i["title"] for i in mine["items"]], ["Mumbai DB slow"])
        self.assertEqual(mine["open"], 1)
        self.assertEqual(len(services.recent_incidents(["PostgreSQL"], user=self.admin)["items"]), 2)

    def test_cancel_link_never_echoes_unsafe_next(self):
        self.client.force_login(self.admin)
        r = self.client.get(reverse("cmdb:item_create") + "?next=javascript:alert(document.cookie)")
        self.assertNotContains(r, "javascript:")
        r = self.client.get(reverse("cmdb:item_create") + "?next=https://evil.example/")
        self.assertNotContains(r, "evil.example")
        r = self.client.get(reverse("cmdb:item_create") + "?next=/assets/")
        self.assertContains(r, 'value="/assets/"')

    def test_lifecycle_job_keeps_changes_beyond_the_cap_for_next_run(self):
        soon = timezone.localdate() + timedelta(days=5)
        for i in range(5):
            ci(f"host-{i}", warranty_end=soon)
        with mock.patch.object(jobs, "MAX_EVENTS", 2):
            jobs.lifecycle_scan()
            self.assertEqual(Event.objects.filter(source="cmdb", kind="lifecycle").count(), 2)
            jobs.lifecycle_scan()
            self.assertEqual(Event.objects.filter(source="cmdb", kind="lifecycle").count(), 4)
            jobs.lifecycle_scan()
        self.assertEqual(Event.objects.filter(source="cmdb", kind="lifecycle").count(), 5)
        self.assertFalse(ConfigurationItem.objects.filter(name__startswith="host-", lifecycle_flag="").exists())
        jobs.lifecycle_scan()
        self.assertEqual(Event.objects.filter(source="cmdb", kind="lifecycle").count(), 5)

    def test_viewer_license_links_do_not_lead_to_403(self):
        lic = License.objects.create(tenant_key=T, product="RHEL sub", seats=0,
                                     expiry=timezone.localdate() + timedelta(days=10))
        sw = Software.objects.create(tenant_key=T, name="RHEL")
        lic.software = sw
        lic.save()
        sw.installs.add(self.mum_db)
        edit = reverse("cmdb:license_edit", args=[lic.pk])
        self.client.force_login(self.viewer)
        for url in (reverse("cmdb:licenses"), reverse("cmdb:lifecycle"), reverse("cmdb:software_detail", args=[sw.pk])):
            r = self.client.get(url)
            self.assertEqual(r.status_code, 200, url)
            self.assertNotContains(r, edit)
        self.client.force_login(self.admin)
        self.assertContains(self.client.get(reverse("cmdb:licenses")), edit)

    def test_lifecycle_list_is_paginated(self):
        soon = timezone.localdate() + timedelta(days=5)
        for i in range(30):
            ci(f"box-{i:02d}", warranty_end=soon)
        self.client.force_login(self.viewer)
        r = self.client.get(reverse("cmdb:lifecycle"))
        self.assertEqual(r.context["page"].paginator.count, 30)
        self.assertEqual(len(r.context["page"].object_list), 25)
        r = self.client.get(reverse("cmdb:lifecycle") + "?page=2")
        self.assertContains(r, "box-29")

    def test_software_form_only_offers_manageable_items_and_keeps_others(self):
        sw = Software.objects.create(tenant_key=T, name="Agent")
        sw.installs.add(self.platform.pk and ci("global-host", site="All Sites"))
        from .forms import SoftwareForm
        form = SoftwareForm(user=self.siteop)
        offered = set(form.fields["installs"].queryset.values_list("name", flat=True))
        self.assertEqual(offered, {"PostgreSQL"})
        self.client.force_login(self.siteop)
        r = self.client.post(reverse("cmdb:software_edit", args=[sw.pk]),
                             {"name": "Agent", "version": "", "installs": [self.mum_db.pk]})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(set(sw.installs.values_list("name", flat=True)), {"global-host", "PostgreSQL"})

    def test_domain_chain_is_bounded_on_dense_graphs(self):
        # a complete layered DAG: unbounded DFS would explore every path
        layers = [[ci(f"n{l}-{i}", "application", business_domain="Dense") for i in range(8)] for l in range(7)]
        for a, b in zip(layers, layers[1:]):
            for x in a:
                for y in b:
                    rel(x, y, "depends_on")
        d = hm.build(self.admin)
        dom = next(x for x in d["domains"] if x["name"] == "Dense")
        visits = []
        real = services.dependency_adjacency

        class Counting(dict):
            def get(self, key, default=None):
                visits.append(key)
                return super().get(key, default)

        with mock.patch.object(services, "dependency_adjacency", lambda edges: Counting(real(edges))), \
                mock.patch.object(hm, "MAX_CHAIN_STEPS", 300):
            chain = hm.domain_chain(dom, d["edges"], d["ci_map"], {})
        self.assertLessEqual(len(visits), 300 + 6)   # unbounded this graph needs ~40,000 steps
        self.assertEqual(len(chain), 6)

    def test_seed_reuses_existing_item_with_different_case(self):
        ci("oms", "application")
        call_command("seed_cmdb", stdout=io.StringIO())
        self.assertEqual(ConfigurationItem.objects.filter(name__iexact="oms").count(), 1)

    def test_list_actions_follow_the_row_site(self):
        self.client.force_login(self.siteop)
        edit_global, edit_mine = reverse("cmdb:item_edit", args=[self.platform.pk]), reverse("cmdb:item_edit", args=[self.mum_db.pk])
        r = self.client.get(reverse("cmdb:items"))
        self.assertContains(r, edit_mine)
        self.assertNotContains(r, edit_global)
        host = ci("mum-host", "server", site="Mumbai (NSE)")
        glob = ci("glob-host", "server", site="All Sites")
        r = self.client.get(reverse("cmdb:assets"))
        self.assertContains(r, reverse("cmdb:item_edit", args=[host.pk]))
        self.assertNotContains(r, reverse("cmdb:item_edit", args=[glob.pk]))
        sw = Software.objects.create(tenant_key=T, name="Agent")
        sw.installs.add(host, glob)
        r = self.client.get(reverse("cmdb:software_detail", args=[sw.pk]))
        self.assertContains(r, f'name="remove" value="{host.pk}"')
        self.assertNotContains(r, f'name="remove" value="{glob.pk}"')
        self.assertNotContains(r, f'<option value="{self.platform.pk}"')
        # a site admin only gets delete buttons for relationships whose source is on their site
        sadmin = User.objects.create_user("sadmin")
        Membership.objects.create(user=sadmin, site=self.mum, role="admin")
        other = ci("dr-db", "database", site="All Sites")
        r1 = rel(self.mum_db, other, "connects_to")
        r2 = rel(other, self.mum_db, "depends_on")
        self.client.force_login(sadmin)
        r = self.client.get(reverse("cmdb:relationships"))
        self.assertContains(r, reverse("cmdb:relationship_delete", args=[r1.pk]))
        self.assertNotContains(r, reverse("cmdb:relationship_delete", args=[r2.pk]))
        r = self.client.get(reverse("cmdb:item_detail", args=[self.mum_db.pk]))
        self.assertContains(r, reverse("cmdb:relationship_delete", args=[r1.pk]))
        self.assertNotContains(r, reverse("cmdb:relationship_delete", args=[r2.pk]))

    def test_asset_kpis_match_the_lists_they_link_to(self):
        today = timezone.localdate()
        ci("eol-past", "server", eol_date=today - timedelta(days=3))
        ci("eol-soon", "server", eol_date=today + timedelta(days=100))
        ci("eol-retired", "server", eol_date=today - timedelta(days=3), status="retired")
        ci("wty-out-retired", "server", warranty_end=today - timedelta(days=3), status="retired")
        self.client.force_login(self.admin)
        r = self.client.get(reverse("cmdb:assets"))
        self.assertEqual(r.context["eol_due"], 2)
        self.assertContains(r, 'href="?lifecycle=eol_due"')
        r = self.client.get(reverse("cmdb:assets") + "?lifecycle=eol_due")
        self.assertEqual({c.name for c in r.context["page"]}, {"eol-past", "eol-soon"})
        r = self.client.get(reverse("cmdb:assets") + "?lifecycle=warranty_expired")
        self.assertEqual(r.context["page"].paginator.count, r.context["warranty_expired"])

    def test_top_services_highlight_follows_metric_grade(self):
        from urlchecker.models import UrlCheck
        svc = ci("Pay API", "service", business_domain="Payments")
        chk = UrlCheck.objects.create(tenant_key=T, name="pay", url="https://pay.example/", degraded_ms=1000)
        svc.url_checks.add(chk)
        now = timezone.now()
        for i in range(10):
            UrlResult.objects.create(url_check=chk, checked_at=now - timedelta(minutes=i), status="online",
                                     http_status=200, response_ms=100)
        ci("Idle API", "service", business_domain="Payments", prometheus_instance="idle:9100")   # CPU critical, no probes
        self.client.force_login(self.admin)
        with override_settings(PROMETHEUS_URL="http://prom.example:9090"), \
                mock.patch.object(hm, "host_metrics", return_value=({"idle:9100": {"cpu": 99.0}}, "")):
            r = self.client.get(reverse("cmdb:heatmap") + "?domain=Payments")
        self.assertEqual({x["name"]: x["health"] for x in r.context["details"]["rows"]}["Idle API"], "critical")
        rows = {x["name"]: x for x in r.context["details"]["rows"]}
        self.assertFalse(rows["Pay API"]["hot"]["latency"])
        self.assertFalse(rows["Idle API"]["hot"]["latency"])    # no data is grey, never red
        self.assertNotContains(r, '<td class="t-crit">–</td>')


@override_settings(LINKEDEYE_TENANT=T, PROMETHEUS_URL="")
class AdversarialQATests(TestCase):
    """Bugs found by the second end-to-end (adversarial) pass."""

    HUGE = "99999999999999999999999"

    def setUp(self):
        self.mum = Site.objects.create(name="Mumbai (NSE)", code="mum")
        self.admin = User.objects.create_superuser("admin", "a@example.com", "pw")
        self.operator = User.objects.create_user("operator", is_staff=True)
        # viewer on every site, operator on one: must not manage "All Sites" records
        self.mixed = User.objects.create_user("mixed")
        Membership.objects.create(user=self.mixed, site=None, role="viewer")
        Membership.objects.create(user=self.mixed, site=self.mum, role="operator")
        self.glob = ci("Trading", "business_domain", site="All Sites")
        self.mum_host = ci("mum-host-01", "server", site="Mumbai (NSE)")
        self.svc = ci("OMS", "application", site="Mumbai (NSE)")
        self.sw = Software.objects.create(tenant_key=T, name="RHEL", version="9")

    def test_all_sites_records_need_the_global_role(self):
        self.assertFalse(services.can_manage(self.mixed, "operate", "All Sites"))
        self.assertTrue(services.can_manage(self.mixed, "operate", "Mumbai (NSE)"))
        self.assertFalse(services.can_manage(self.mixed, "operate", "DR Site"))
        self.assertTrue(services.can_manage(self.operator, "operate", "All Sites"))
        self.client.force_login(self.mixed)
        self.assertEqual(self.client.get(reverse("cmdb:item_edit", args=[self.glob.pk])).status_code, 403)
        self.assertEqual(self.client.get(reverse("cmdb:item_edit", args=[self.mum_host.pk])).status_code, 200)
        r = self.client.post(reverse("cmdb:item_create"), {"name": "global-x", "ci_type": "server", "status": "active",
                                                           "environment": "prod", "site": "All Sites"})
        self.assertEqual(r.status_code, 200)
        self.assertFalse(ConfigurationItem.objects.filter(name="global-x").exists())
        r = self.client.get(reverse("cmdb:items"))
        rows = {c.name: c for c in r.context["page"]}
        self.assertFalse(rows["Trading"].can_edit)
        self.assertTrue(rows["mum-host-01"].can_edit)

    def test_out_of_range_ids_are_not_server_errors(self):
        self.client.force_login(self.admin)
        for name in ("item_detail", "item_edit", "software_detail", "software_edit", "license_edit"):
            self.assertEqual(self.client.get(f"/{'cmdb/items' if 'item' in name else 'assets/software' if 'software' in name else 'assets/licenses'}/{self.HUGE}/"
                                             + ("edit/" if "edit" in name else "")).status_code, 404, name)
        self.assertEqual(self.client.post(f"/cmdb/items/{self.HUGE}/delete/").status_code, 404)
        self.assertEqual(self.client.post(f"/cmdb/relationships/{self.HUGE}/delete/").status_code, 404)
        r = self.client.get(reverse("cmdb:relationships") + f"?ci={self.HUGE}")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.context["page"].paginator.count, 0)
        self.assertEqual(self.client.get(reverse("cmdb:relationships_export") + f"?ci={self.HUGE}").status_code, 200)
        self.assertEqual(self.client.get(reverse("cmdb:license_create") + f"?software={self.HUGE}").status_code, 200)
        for data in ({"ci": self.HUGE}, {"remove": self.HUGE}):
            r = self.client.post(reverse("cmdb:software_installs", args=[self.sw.pk]), data)
            self.assertEqual(r.status_code, 302)
        r = self.client.post(reverse("cmdb:relationship_create"), {"source": self.HUGE, "target": self.svc.pk,
                                                                   "rel_type": "depends_on", "origin": "manual", "confidence": 1})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(Relationship.objects.count(), 0)
        r = self.client.post(reverse("cmdb:item_create"), {"name": "x1", "ci_type": "server", "status": "active",
                                                           "environment": "prod", "site": "All Sites", "url_checks": [self.HUGE]})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.context["form"].errors.get("url_checks"))
        r = self.client.post(reverse("cmdb:software_edit", args=[self.sw.pk]), {"name": "RHEL", "version": "9",
                                                                               "installs": [self.HUGE]})
        self.assertEqual(r.status_code, 200)
        r = self.client.post(reverse("cmdb:license_create"), {"product": "p", "seats": 1, "software": self.HUGE})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.context["form"].errors.get("software"))

    def test_detail_form_can_add_incoming_relationship(self):
        self.client.force_login(self.admin)
        r = self.client.get(reverse("cmdb:item_detail", args=[self.mum_host.pk]))
        target_select = r.content.decode().split('id="rf-target"')[1].split("</select>")[0]
        self.assertIn(f'value="{self.mum_host.pk}"', target_select)   # "OMS runs on <this host>" is possible

    def test_domain_filter_includes_part_of_members(self):
        loose = ci("Settlement", "service", site="Mumbai (NSE)")   # no business_domain text
        rel(loose, self.glob, "part_of")
        self.client.force_login(self.admin)
        r = self.client.get(reverse("cmdb:items") + "?domain=Trading")
        self.assertEqual({c.name for c in r.context["page"]}, {"Trading", "Settlement"})
        _dom, members = services.domain_members("Trading")
        self.assertEqual({c.name for c in members}, {"Settlement"})

    def test_import_reports_malformed_csv_instead_of_crashing(self):
        self.client.force_login(self.admin)
        text = "name,description\nok-row,fine\nbig-row," + "x" * 200000 + "\n"
        r = self.client.post(reverse("cmdb:items_import"), {"file": SimpleUploadedFile("a.csv", text.encode())})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(any("not valid CSV" in m for _n, m in r.context["result"]["errors"]))
        self.assertFalse(ConfigurationItem.objects.filter(name="ok-row").exists())
        r = self.client.post(reverse("cmdb:items_import"), {"file": SimpleUploadedFile("h.csv", ("x" * 200000 + "\n").encode())})
        self.assertEqual(r.status_code, 200)

    def test_export_import_round_trip_keeps_formula_like_values(self):
        c = ci("-backup", "server", site="Mumbai (NSE)", description="=1+1 is not a formula", owner="@ops")
        self.client.force_login(self.admin)
        body = self.client.get(reverse("cmdb:items_export") + "?q=backup").content
        self.assertIn(b"'-backup", body)
        r = self.client.post(reverse("cmdb:items_import"), {"file": SimpleUploadedFile("rt.csv", body), "update_existing": "on"})
        self.assertEqual(r.status_code, 302, r.context and r.context["result"]["errors"])
        self.assertFalse(ConfigurationItem.objects.filter(name="'-backup").exists())
        c.refresh_from_db()
        self.assertEqual((c.description, c.owner), ("=1+1 is not a formula", "@ops"))

    def test_software_export_has_no_per_row_queries(self):
        self.client.force_login(self.admin)

        def count():
            from django.db import connection
            from django.test.utils import CaptureQueriesContext
            with CaptureQueriesContext(connection) as q:
                self.assertEqual(self.client.get(reverse("cmdb:software_export")).status_code, 200)
            return len(q)
        self.sw.installs.add(self.mum_host)
        before = count()
        for i in range(5):
            Software.objects.create(tenant_key=T, name=f"sw{i}").installs.add(self.svc)
        self.assertEqual(count(), before)
        self.assertIn("mum-host-01", self.client.get(reverse("cmdb:software_export")).content.decode())

    def test_relationship_list_names_the_item_filter(self):
        rel(self.svc, self.mum_host, "runs_on")
        self.client.force_login(self.admin)
        r = self.client.get(reverse("cmdb:relationships") + f"?ci={self.svc.pk}")
        self.assertContains(r, "cm-ci-filter")
        self.assertEqual(r.context["form"]["source"].value(), self.svc.pk)

    def test_relationship_counts_ignore_items_on_hidden_sites(self):
        siteop = User.objects.create_user("siteop2")
        Membership.objects.create(user=siteop, site=self.mum, role="operator")
        dr = ci("dr-db-01", "server", site="DR Site")
        rel(self.svc, self.mum_host, "runs_on")
        rel(self.svc, dr, "depends_on")
        self.client.force_login(siteop)
        r = self.client.get(reverse("cmdb:items"))
        oms = next(c for c in r.context["page"] if c.name == "OMS")
        self.assertEqual((oms.n_out, oms.n_in), (1, 0))
        self.assertEqual(r.context["relationships"], 1)
        self.client.force_login(self.admin)
        oms = next(c for c in self.client.get(reverse("cmdb:items")).context["page"] if c.name == "OMS")
        self.assertEqual(oms.n_out, 2)
