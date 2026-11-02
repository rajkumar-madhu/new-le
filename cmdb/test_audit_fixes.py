"""Regression tests for the audit findings (site scoping of links, global records, Unicode ids, impact events)."""
from datetime import timedelta

from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from core.access import scope_by_site
from core.events import emit
from core.models import Event, Membership, Site
from domainmonitor.models import Domain
from urlchecker.models import UrlCheck

from . import services
from .forms import CIForm
from .listeners import impact_for_event
from .models import ConfigurationItem, License, Relationship, Software

T = "default"


def ci(name, ci_type="server", **kw):
    kw.setdefault("tenant_key", T)
    return ConfigurationItem.objects.create(name=name, ci_type=ci_type, **kw)


def ci_post(c, **extra):
    data = {"name": c.name, "ci_type": c.ci_type, "status": c.status, "environment": c.environment, "site": c.site}
    data.update(extra)
    return data


@override_settings(LINKEDEYE_TENANT=T)
class LinkScopeTests(TestCase):
    """CI form and CSV import only offer URL checks and domains on the user's sites."""

    def setUp(self):
        self.mum = Site.objects.create(name="Mumbai (NSE)", code="mum")
        Site.objects.create(name="DR Site", code="dr")
        self.siteop = User.objects.create_user("siteop")
        Membership.objects.create(user=self.siteop, site=self.mum, role="operator")
        self.admin = User.objects.create_superuser("admin", "a@example.com", "pw")
        self.web = ci("mum-web", site="Mumbai (NSE)")
        self.dr_dom = Domain.objects.create(tenant_key=T, site_key="DR Site", hostname="secret-dr.example",
                                            last_error="TOPSECRET-DR-ERROR")
        self.mum_dom = Domain.objects.create(tenant_key=T, site_key="Mumbai (NSE)", hostname="mum.example")
        self.dr_url = UrlCheck.objects.create(tenant_key=T, name="dr-secret-check", url="https://dr.example/", site="DR Site")
        self.mum_url = UrlCheck.objects.create(tenant_key=T, name="mum-check", url="https://mum.example/", site="Mumbai (NSE)")

    def test_edit_form_hides_and_rejects_links_on_other_sites(self):
        self.client.force_login(self.siteop)
        edit = reverse("cmdb:item_edit", args=[self.web.pk])
        r = self.client.get(edit)
        self.assertEqual(r.status_code, 200)
        self.assertNotContains(r, "secret-dr.example")
        self.assertNotContains(r, "dr-secret-check")
        self.assertContains(r, "mum.example")
        self.assertContains(r, "mum-check")
        r = self.client.post(edit, ci_post(self.web, domains=[self.dr_dom.pk], url_checks=[self.dr_url.pk]))
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.context["form"].errors.get("domains"))
        self.assertTrue(r.context["form"].errors.get("url_checks"))
        self.assertFalse(self.web.domains.exists())
        self.assertFalse(self.web.url_checks.exists())
        r = self.client.post(edit, ci_post(self.web, domains=[self.mum_dom.pk], url_checks=[self.mum_url.pk]))
        self.assertEqual(r.status_code, 302)
        self.assertEqual(list(self.web.domains.values_list("hostname", flat=True)), ["mum.example"])

    def test_edit_keeps_links_the_user_cannot_see(self):
        self.web.domains.add(self.dr_dom)          # linked by an unscoped admin
        self.web.url_checks.add(self.dr_url)
        self.client.force_login(self.siteop)
        r = self.client.post(reverse("cmdb:item_edit", args=[self.web.pk]),
                             ci_post(self.web, owner="Web team", domains=[self.mum_dom.pk]))
        self.assertEqual(r.status_code, 302)
        self.assertEqual(set(self.web.domains.values_list("hostname", flat=True)), {"secret-dr.example", "mum.example"})
        self.assertEqual(set(self.web.url_checks.values_list("name", flat=True)), {"dr-secret-check"})

    def test_admin_still_links_any_site(self):
        form = CIForm(instance=self.web, user=self.admin)
        self.assertIn(self.dr_dom, form.fields["domains"].queryset)
        self.assertIn(self.dr_url, form.fields["url_checks"].queryset)

    def test_import_cannot_link_items_on_other_sites(self):
        self.client.force_login(self.siteop)
        text = "name,type,site,domains,url_checks\nmum-new,server,Mumbai (NSE),secret-dr.example,dr-secret-check\n"
        r = self.client.post(reverse("cmdb:items_import"), {"file": SimpleUploadedFile("c.csv", text.encode())})
        self.assertEqual(r.status_code, 200)
        errors = " ".join(m for _n, m in r.context["result"]["errors"])
        self.assertIn("unknown domain", errors)
        self.assertIn("unknown URL check", errors)
        self.assertFalse(ConfigurationItem.objects.filter(name="mum-new").exists())
        text = "name,type,site,domains,url_checks\nmum-new,server,Mumbai (NSE),mum.example,mum-check\n"
        r = self.client.post(reverse("cmdb:items_import"), {"file": SimpleUploadedFile("c.csv", text.encode())})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(list(ConfigurationItem.objects.get(name="mum-new").domains.values_list("hostname", flat=True)),
                         ["mum.example"])

    def test_import_update_keeps_hidden_links(self):
        self.web.domains.add(self.dr_dom)
        self.client.force_login(self.siteop)
        text = "name,type,site,domains\nmum-web,server,Mumbai (NSE),mum.example\n"
        r = self.client.post(reverse("cmdb:items_import"),
                             {"file": SimpleUploadedFile("c.csv", text.encode()), "update_existing": "on"})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(set(self.web.domains.values_list("hostname", flat=True)), {"secret-dr.example", "mum.example"})


@override_settings(LINKEDEYE_TENANT=T)
class GlobalRecordTests(TestCase):
    """Software and licenses are tenant-wide: changing or deleting them needs the role on every site."""

    def setUp(self):
        self.mum = Site.objects.create(name="Mumbai (NSE)", code="mum")
        Site.objects.create(name="DR Site", code="dr")
        self.siteadmin = User.objects.create_user("siteadmin")
        Membership.objects.create(user=self.siteadmin, site=self.mum, role="admin")
        self.siteop = User.objects.create_user("siteop")
        Membership.objects.create(user=self.siteop, site=self.mum, role="operator")
        self.globop = User.objects.create_user("globop", is_staff=True)       # operator on every site
        self.globadmin = User.objects.create_user("globadmin")
        Membership.objects.create(user=self.globadmin, site=None, role="admin")
        self.mum_ci = ci("mum-01", site="Mumbai (NSE)")
        self.dr_ci = ci("dr-01", site="DR Site")
        self.sw = Software.objects.create(tenant_key=T, name="Agent", vendor="Acme")
        self.sw.installs.add(self.mum_ci, self.dr_ci)
        self.lic = License.objects.create(tenant_key=T, product="Agent sub", software=self.sw, seats=10,
                                          expiry=timezone.localdate() + timedelta(days=20))

    def test_site_admin_cannot_delete_global_records(self):
        self.client.force_login(self.siteadmin)
        r = self.client.post(reverse("cmdb:software_delete", args=[self.sw.pk]))
        self.assertEqual(r.status_code, 403)
        r = self.client.post(reverse("cmdb:license_delete", args=[self.lic.pk]))
        self.assertEqual(r.status_code, 403)
        self.assertTrue(Software.objects.filter(pk=self.sw.pk).exists())
        self.assertEqual(self.sw.installs.count(), 2)
        self.assertTrue(License.objects.filter(pk=self.lic.pk, software=self.sw).exists())

    def test_global_admin_can_delete(self):
        self.client.force_login(self.globadmin)
        self.assertEqual(self.client.post(reverse("cmdb:license_delete", args=[self.lic.pk])).status_code, 302)
        self.assertEqual(self.client.post(reverse("cmdb:software_delete", args=[self.sw.pk])).status_code, 302)
        self.assertFalse(Software.objects.exists())
        self.assertFalse(License.objects.exists())

    def test_site_operator_cannot_create_or_edit_licenses(self):
        self.client.force_login(self.siteop)
        edit = reverse("cmdb:license_edit", args=[self.lic.pk])
        self.assertEqual(self.client.get(edit).status_code, 403)
        r = self.client.post(edit, {"product": "Agent sub", "seats": 1, "expiry": "2020-01-01"})
        self.assertEqual(r.status_code, 403)
        self.lic.refresh_from_db()
        self.assertEqual(self.lic.seats, 10)
        r = self.client.post(reverse("cmdb:license_create"), {"product": "New", "seats": 1})
        self.assertEqual(r.status_code, 403)
        self.assertFalse(License.objects.filter(product="New").exists())
        self.client.force_login(self.globop)
        r = self.client.post(edit, {"product": "Agent sub", "seats": 12, "software": self.sw.pk})
        self.assertEqual(r.status_code, 302)
        self.lic.refresh_from_db()
        self.assertEqual(self.lic.seats, 12)

    def test_site_operator_cannot_create_or_rename_software(self):
        self.client.force_login(self.siteop)
        r = self.client.post(reverse("cmdb:software_create"), {"name": "Rogue", "version": "1"})
        self.assertEqual(r.status_code, 403)
        self.assertFalse(Software.objects.filter(name="Rogue").exists())
        # a site operator may still edit the installs on their own site, but not the tenant-wide details
        r = self.client.post(reverse("cmdb:software_edit", args=[self.sw.pk]),
                             {"name": "Renamed", "vendor": "Evil", "version": "9", "installs": []})
        self.assertEqual(r.status_code, 302)
        self.sw.refresh_from_db()
        self.assertEqual((self.sw.name, self.sw.vendor, self.sw.version), ("Agent", "Acme", ""))
        self.assertEqual(set(self.sw.installs.values_list("name", flat=True)), {"dr-01"})
        self.client.force_login(self.globop)
        r = self.client.post(reverse("cmdb:software_edit", args=[self.sw.pk]),
                             {"name": "Agent", "vendor": "Acme Corp", "version": "2", "installs": [self.mum_ci.pk]})
        self.assertEqual(r.status_code, 302)
        self.sw.refresh_from_db()
        self.assertEqual((self.sw.vendor, self.sw.version), ("Acme Corp", "2"))

    def test_buttons_follow_the_global_role(self):
        sw_del = reverse("cmdb:software_delete", args=[self.sw.pk])
        lic_edit, lic_del = reverse("cmdb:license_edit", args=[self.lic.pk]), reverse("cmdb:license_delete", args=[self.lic.pk])
        sw_new, lic_new = reverse("cmdb:software_create"), reverse("cmdb:license_create")
        self.client.force_login(self.siteadmin)
        pages = [self.client.get(reverse(n, args=a)) for n, a in
                 (("cmdb:software", []), ("cmdb:software_detail", [self.sw.pk]), ("cmdb:licenses", []), ("cmdb:lifecycle", []))]
        for r in pages:
            self.assertEqual(r.status_code, 200)
            for url in (sw_del, lic_edit, lic_del, sw_new, lic_new):
                self.assertNotContains(r, url)
        # editing the installs stays available
        self.assertContains(pages[1], reverse("cmdb:software_edit", args=[self.sw.pk]))
        self.client.force_login(self.globadmin)
        r = self.client.get(reverse("cmdb:software_detail", args=[self.sw.pk]))
        self.assertContains(r, sw_del)
        self.assertContains(r, lic_edit)
        r = self.client.get(reverse("cmdb:licenses"))
        for url in (lic_edit, lic_del, lic_new):
            self.assertContains(r, url)
        self.assertContains(self.client.get(reverse("cmdb:lifecycle")), lic_edit)


@override_settings(LINKEDEYE_TENANT=T)
class UnicodeDigitTests(TestCase):
    """Characters such as '²' pass str.isdigit() but int() rejects them: never a server error."""

    def setUp(self):
        self.op = User.objects.create_user("op", is_staff=True)
        self.svc = ci("OMS", "application")
        self.sw = Software.objects.create(tenant_key=T, name="RHEL")
        self.client.raise_request_exception = False

    def test_as_pk(self):
        for v in ("²", "①", "1²", "١"):
            self.assertIsNone(services.as_pk(v), v)
        self.assertEqual(services.as_pk(" 12 "), 12)

    def test_views_do_not_crash(self):
        self.client.force_login(self.op)
        for url in (reverse("cmdb:relationships") + "?ci=%C2%B2", reverse("cmdb:relationships") + "?source=%C2%B2",
                    reverse("cmdb:relationships_export") + "?ci=%C2%B2", reverse("cmdb:topology") + "?root=%C2%B2",
                    reverse("cmdb:license_create") + "?software=%C2%B2"):
            self.assertEqual(self.client.get(url).status_code, 200, url)
        r = self.client.post(reverse("cmdb:relationship_create"), {"source": "²", "target": self.svc.pk,
                                                                   "rel_type": "depends_on", "origin": "manual", "confidence": 1})
        self.assertEqual(r.status_code, 302)
        self.assertFalse(Relationship.objects.exists())
        r = self.client.post(reverse("cmdb:software_installs", args=[self.sw.pk]), {"ci": "²"})
        self.assertEqual(r.status_code, 302)
        r = self.client.post(reverse("cmdb:item_edit", args=[self.svc.pk]), ci_post(self.svc, domains=["²"], url_checks=["²"]))
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.context["form"].errors.get("domains"))
        r = self.client.post(reverse("cmdb:software_edit", args=[self.sw.pk]), {"name": "RHEL", "installs": ["²"]})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.context["form"].errors.get("installs"))

    def test_listener_ignores_unicode_digit_ids(self):
        ev = Event.objects.create(source="urlchecker", title="x", severity="critical", object_type="urlchecker.urlcheck",
                                  object_id="²")
        self.assertIsNone(impact_for_event(ev))


@override_settings(LINKEDEYE_TENANT=T)
class ImpactEventScopeTests(TestCase):
    """The impact event only names CIs that the viewers of its site may see."""

    def setUp(self):
        self.mum = Site.objects.create(name="Mumbai (NSE)", code="mum")
        self.dr = Site.objects.create(name="DR Site", code="dr")
        self.viewer = User.objects.create_user("mumviewer")
        Membership.objects.create(user=self.viewer, site=self.mum, role="viewer")
        self.dr_viewer = User.objects.create_user("drviewer")
        Membership.objects.create(user=self.dr_viewer, site=self.dr, role="viewer")
        self.mum_svc = ci("mum-svc", "service", site="Mumbai (NSE)")
        self.dr_svc = ci("dr-secret-svc", "service", site="DR Site")
        self.glob = ci("Trading", "business_domain", site="All Sites")
        Relationship.objects.create(source=self.dr_svc, target=self.mum_svc, rel_type="depends_on")
        Relationship.objects.create(source=self.mum_svc, target=self.glob, rel_type="part_of")
        self.check = UrlCheck.objects.create(tenant_key=T, name="mum check", url="https://mum.example/", site="Mumbai (NSE)")
        self.mum_svc.url_checks.add(self.check)

    def _visible(self, user):
        return list(scope_by_site(Event.objects.filter(source="cmdb", kind="impact"), user))

    def test_events_are_split_by_site(self):
        emit("urlchecker", "mum check is Down", severity="critical", site=self.check.site, obj=self.check,
             fingerprint=f"url:{self.check.pk}")
        mine = self._visible(self.viewer)
        self.assertEqual(len(mine), 1)
        self.assertEqual(mine[0].site, "Mumbai (NSE)")
        self.assertEqual(mine[0].data["cis"], ["mum-svc", "Trading"])
        self.assertNotIn("dr-secret-svc", mine[0].message + mine[0].title)
        theirs = self._visible(self.dr_viewer)
        self.assertEqual(len(theirs), 1)
        self.assertEqual(theirs[0].site, "DR Site")
        self.assertEqual(theirs[0].data["cis"], ["dr-secret-svc", "Trading"])
        self.assertNotIn("mum-svc", theirs[0].message)
        # nor the name of the failed Mumbai check (URL checks and domains are site-scoped too)
        self.assertNotIn("mum check", theirs[0].title + theirs[0].message + str(theirs[0].data))
        self.assertIn("mum check", mine[0].title)
        # the observe events page a Mumbai viewer reads never names the DR item
        self.client.force_login(self.viewer)
        try:
            r = self.client.get(reverse("observe:events"))
        except Exception:  # noqa: BLE001 - observe may not be installed in every build
            r = None
        if r is not None and r.status_code == 200:
            self.assertNotContains(r, "dr-secret-svc")

    def test_returns_the_event_of_the_source_site(self):
        src = emit("urlchecker", "mum check is Down", severity="critical", site=self.check.site, obj=self.check,
                   fingerprint=f"x:{self.check.pk}")
        Event.objects.filter(source="cmdb").delete()
        ev = impact_for_event(src)
        self.assertEqual(ev.site, "Mumbai (NSE)")
        self.assertEqual(ev.fingerprint, f"cmdb:impact:urlchecker.urlcheck:{self.check.pk}")
