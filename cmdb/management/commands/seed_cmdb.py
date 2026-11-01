"""Create clearly-marked example CMDB data: business domains, services, hosts, relationships,
software and licenses. Idempotent; links services to the example URL checks / domains from
`manage.py seed_examples` by name when they exist. `--clear` removes the examples again."""
import zlib
from datetime import timedelta
from decimal import Decimal

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from cmdb.models import ConfigurationItem, License, Relationship, Software

MARK = "Example: "

DOMAINS = [
    ("Trading", "Trading and order management systems"),
    ("External Services", "Third party and exchange services"),
    ("Corporate Web", "Public corporate websites"),
    ("Platform", "Shared databases, messaging and identity"),
    ("Applications", "Internal business and operations applications"),
]

# name, type, domain, env, site, owner, description, url checks, domains, prometheus instance
SERVICES = [
    ("OMS", "application", "Trading", "prod", "Mumbai (NSE)", "Trading Apps", "Order management system", [], [], ""),
    ("Order Gateway", "service", "Trading", "prod", "Mumbai (NSE)", "Trading Apps", "Order routing to exchanges", [], [], ""),
    ("Trade Adapter", "service", "Trading", "prod", "Mumbai (NSE)", "Trading Apps", "Exchange trade feed adapter", [], [], ""),
    ("Risk Engine", "application", "Trading", "prod", "Mumbai (NSE)", "Risk Team", "Pre-trade and intraday risk", [], [], ""),
    ("Market Data", "service", "Trading", "prod", "Mumbai (NSE)", "Market Data Team", "Exchange market data feeds",
     ["NSE Web Portal", "BSE Portal"], ["nseindia.com", "bseindia.com"], ""),
    ("Exchange APIs", "service", "External Services", "prod", "All Sites", "Network Team", "NSE, BSE and MCX public endpoints",
     ["NSE Web Portal", "BSE Portal", "MCX Portal"], ["nseindia.com", "bseindia.com", "mcxindia.com"], ""),
    ("GitHub API", "service", "External Services", "prod", "All Sites", "DevOps", "Source hosting and CI dependency",
     ["GitHub API"], ["api.github.com"], ""),
    ("Finspot Website", "application", "Corporate Web", "prod", "All Sites", "Marketing", "finspot.in public website",
     ["Finspot Website"], ["finspot.in"], ""),
    ("WeCrew Website", "application", "Corporate Web", "prod", "All Sites", "Marketing", "wecrew.in public website",
     ["WeCrew Website"], ["wecrew.in"], ""),
    ("PostgreSQL", "database", "Platform", "prod", "Mumbai (NSE)", "DBA Team", "Primary OLTP database cluster", [], [], ""),
    ("Redis", "database", "Platform", "prod", "Mumbai (NSE)", "Platform Team", "Cache and session store", [], [], ""),
    ("RabbitMQ", "middleware", "Platform", "prod", "Mumbai (NSE)", "Platform Team", "Message broker", [], [], ""),
    ("Keycloak", "application", "Platform", "prod", "All Sites", "Security Team", "Single sign-on", ["Keycloak"], [], ""),
    ("Customer Portal", "application", "Corporate Web", "prod", "All Sites", "Digital Team", "Client self-service portal",
     ["Customer Portal"], [], ""),
    ("Redmine", "application", "Applications", "prod", "All Sites", "IT Service Desk", "Ticketing (Redmine)", ["Redmine"], [], ""),
    ("Grafana", "application", "Applications", "prod", "All Sites", "Monitoring Team", "Dashboards", ["Grafana"], [], ""),
    ("Superset", "application", "Applications", "prod", "All Sites", "Data Team", "Analytics dashboards", ["Superset"], [], ""),
    ("LinkedEye API", "service", "Applications", "prod", "All Sites", "Monitoring Team", "LinkedEye platform API",
     ["LinkedEye API"], [], ""),
    ("Reference Site", "service", "Platform", "dr", "DR Site", "Platform Team", "IANA reference endpoint used as a canary",
     ["Example (IANA)"], ["example.com"], ""),
]

# name, type, env, site, ip, vendor, model, serial, purchase (days ago), warranty (days from today), eol (days), cost, prometheus
HOSTS = [
    ("prod-oms-01", "server", "prod", "Mumbai (NSE)", "10.10.1.21", "Dell", "PowerEdge R650", "EX-7HX2K93", 1100, 25, 400, "9800", "prod-oms-01:9100"),
    ("prod-oms-02", "server", "prod", "Mumbai (NSE)", "10.10.1.22", "Dell", "PowerEdge R650", "EX-7HX2K94", 1100, 25, 400, "9800", "prod-oms-02:9100"),
    ("prod-db-01", "server", "prod", "Mumbai (NSE)", "10.10.2.11", "HPE", "ProLiant DL380 Gen10", "EX-CZJ0314", 1600, -40, 150, "14500", "prod-db-01:9100"),
    ("prod-k8s-node-01", "virtual_machine", "prod", "Mumbai (NSE)", "10.10.3.31", "VMware", "vSphere VM", "", 500, None, None, None, "prod-k8s-node-01:9100"),
    ("prod-k8s-node-02", "virtual_machine", "prod", "Mumbai (NSE)", "10.10.3.32", "VMware", "vSphere VM", "", 500, None, None, None, "prod-k8s-node-02:9100"),
    ("prod-web-01", "virtual_machine", "prod", "All Sites", "10.10.4.41", "VMware", "vSphere VM", "", 300, None, None, None, "prod-web-01:9100"),
    ("dr-oms-01", "server", "dr", "DR Site", "10.20.1.21", "Dell", "PowerEdge R640", "EX-5GT1L02", 1900, -300, -20, "7600", "dr-oms-01:9100"),
    ("core-sw-01", "network_device", "prod", "Mumbai (NSE)", "10.10.0.2", "Cisco", "Nexus 93180YC-FX", "EX-FDO2231", 1300, 75, 160, "12500", ""),
    ("san-01", "storage", "prod", "Mumbai (NSE)", "10.10.0.50", "NetApp", "AFF A250", "EX-NA-7731", 900, 170, 1000, "38000", ""),
]

K8S = ("Kubernetes Platform", "kubernetes_cluster", "prod", "Mumbai (NSE)", "Platform Team", "Production Kubernetes cluster")

# source, relationship, target, origin, confidence
RELS = [
    ("Market Data", "depends_on", "Exchange APIs", "manual", 100),
    ("OMS", "depends_on", "Market Data", "manual", 100),
    ("OMS", "depends_on", "PostgreSQL", "manual", 100),
    ("OMS", "depends_on", "Redis", "manual", 100),
    ("OMS", "runs_on", "prod-oms-01", "manual", 100),
    ("OMS", "runs_on", "prod-oms-02", "manual", 100),
    ("Risk Engine", "depends_on", "OMS", "manual", 100),
    ("Risk Engine", "depends_on", "PostgreSQL", "manual", 100),
    ("Order Gateway", "depends_on", "OMS", "manual", 100),
    ("Order Gateway", "depends_on", "Exchange APIs", "manual", 100),
    ("Trade Adapter", "depends_on", "Order Gateway", "manual", 100),
    ("Trade Adapter", "depends_on", "RabbitMQ", "manual", 100),
    ("Risk Engine", "runs_on", "Kubernetes Platform", "manual", 100),
    ("Trade Adapter", "runs_on", "Kubernetes Platform", "manual", 100),
    ("PostgreSQL", "hosted_on", "prod-db-01", "manual", 100),
    ("Redis", "runs_on", "Kubernetes Platform", "manual", 100),
    ("RabbitMQ", "runs_on", "Kubernetes Platform", "manual", 100),
    ("Keycloak", "runs_on", "Kubernetes Platform", "manual", 100),
    ("Keycloak", "depends_on", "PostgreSQL", "manual", 100),
    ("Kubernetes Platform", "runs_on", "prod-k8s-node-01", "manual", 100),
    ("Kubernetes Platform", "runs_on", "prod-k8s-node-02", "manual", 100),
    ("Finspot Website", "runs_on", "prod-web-01", "manual", 100),
    ("WeCrew Website", "runs_on", "prod-web-01", "manual", 100),
    ("prod-db-01", "depends_on", "san-01", "discovered", 90),
    ("prod-oms-01", "connects_to", "core-sw-01", "discovered", 85),
    ("prod-oms-02", "connects_to", "core-sw-01", "discovered", 85),
    ("prod-db-01", "connects_to", "core-sw-01", "discovered", 85),
    ("Reference Site", "runs_on", "dr-oms-01", "manual", 100),
    ("Redmine", "runs_on", "Kubernetes Platform", "manual", 100),
    ("Redmine", "depends_on", "PostgreSQL", "manual", 100),
    ("Grafana", "runs_on", "Kubernetes Platform", "manual", 100),
    ("Superset", "runs_on", "Kubernetes Platform", "manual", 100),
    ("Superset", "depends_on", "PostgreSQL", "manual", 100),
    ("LinkedEye API", "runs_on", "prod-web-01", "manual", 100),
    ("LinkedEye API", "depends_on", "Redis", "manual", 100),
    ("Customer Portal", "depends_on", "Keycloak", "manual", 100),
    ("Customer Portal", "depends_on", "OMS", "manual", 100),
    ("Customer Portal", "runs_on", "prod-web-01", "manual", 100),
]

# name, version, vendor, category, installed on
SOFTWARE = [
    ("Red Hat Enterprise Linux", "9.4", "Red Hat", "Operating System",
     ["prod-oms-01", "prod-oms-02", "prod-db-01", "prod-k8s-node-01", "prod-k8s-node-02", "prod-web-01", "dr-oms-01"]),
    ("PostgreSQL", "16.4", "PostgreSQL Global Development Group", "Database", ["prod-db-01"]),
    ("Redis", "7.2", "Redis Ltd.", "Database", ["Kubernetes Platform"]),
    ("RabbitMQ", "3.13", "Broadcom", "Middleware", ["Kubernetes Platform"]),
    ("Keycloak", "24.0", "Red Hat", "Identity", ["Kubernetes Platform"]),
    ("Eclipse Temurin JDK", "17", "Eclipse Adoptium", "Runtime", ["prod-oms-01", "prod-oms-02", "dr-oms-01"]),
    ("Nginx", "1.26", "F5", "Web Server", ["prod-web-01"]),
    ("node_exporter", "1.8.2", "Prometheus", "Monitoring",
     ["prod-oms-01", "prod-oms-02", "prod-db-01", "prod-k8s-node-01", "prod-k8s-node-02", "prod-web-01", "dr-oms-01"]),
    ("VMware vSphere", "8.0", "Broadcom", "Virtualization", []),
]

# product, vendor, software name, type, seats, expiry (days from today), cost, reference
LICENSES = [
    ("RHEL Server Subscription", "Red Hat", "Red Hat Enterprise Linux", "Subscription", 6, 45, "5400", "EX-RH-2025-114"),
    ("EDB Postgres Support", "EnterpriseDB", "PostgreSQL", "Support", 2, 210, "8200", "EX-EDB-883"),
    ("Red Hat build of Keycloak", "Red Hat", "Keycloak", "Subscription", 2, -12, "3100", "EX-RH-2024-071"),
    ("VMware vSphere Enterprise Plus", "Broadcom", "VMware vSphere", "Per core", 32, 75, "21000", "EX-VMW-5521"),
    ("RabbitMQ Commercial Support", "Broadcom", "RabbitMQ", "Support", 1, 330, "2600", "EX-RMQ-019"),
]


def _days(n):
    return None if n is None else timezone.localdate() + timedelta(days=n)


class Command(BaseCommand):
    help = "Create example CMDB records (marked 'Example:' / attributes.example) for demos. Idempotent."

    def add_arguments(self, parser):
        parser.add_argument("--clear", action="store_true", help="Delete the example CMDB records instead.")

    def handle(self, *args, **opts):
        tenant = settings.LINKEDEYE_TENANT
        if opts["clear"]:
            n = ConfigurationItem.objects.filter(tenant_key=tenant, attributes__example=True).delete()[0]
            n += Software.objects.filter(tenant_key=tenant, description__startswith=MARK).delete()[0]
            n += License.objects.filter(tenant_key=tenant, notes__startswith=MARK).delete()[0]
            self.stdout.write(self.style.SUCCESS(f"Deleted {n} example record(s)."))
            return
        with transaction.atomic():
            created = self._seed(tenant)
        self.stdout.write(self.style.SUCCESS(f"Created {created} example CMDB record(s). Open /monitoring/heatmap/ or /cmdb/topology/."))

    def _ci(self, tenant, name, **fields):
        fields.setdefault("attributes", {"example": True})
        fields["description"] = MARK + fields.get("description", "")
        obj, created = ConfigurationItem.objects.get_or_create(tenant_key=tenant, name=name, defaults=fields)
        return obj, created

    def _seed(self, tenant):
        from domainmonitor.models import Domain
        from urlchecker.models import UrlCheck
        checks = {u.name: u for u in UrlCheck.objects.filter(tenant_key=tenant)}
        doms = {d.hostname: d for d in Domain.objects.filter(tenant_key=tenant)}
        n = 0
        cis = {}
        for name, desc in DOMAINS:
            cis[name], c = self._ci(tenant, name, ci_type="business_domain", environment="prod", site="All Sites",
                                    owner="Service Owners", business_domain=name, description=desc)
            n += c
        for name, typ, dom, env, site, owner, desc, urls, hosts, inst in SERVICES:
            ci, c = self._ci(tenant, name, ci_type=typ, environment=env, site=site, owner=owner, business_domain=dom,
                             description=desc, prometheus_instance=inst)
            n += c
            cis[name] = ci
            if c:
                ci.url_checks.set([checks[u] for u in urls if u in checks])
                ci.domains.set([doms[h] for h in hosts if h in doms])
            else:   # checks seeded later: add missing links without touching user changes
                ci.url_checks.add(*[checks[u] for u in urls if u in checks])
                ci.domains.add(*[doms[h] for h in hosts if h in doms])
        name, typ, env, site, owner, desc = K8S
        cis[name], c = self._ci(tenant, name, ci_type=typ, environment=env, site=site, owner=owner, business_domain="Platform",
                                description=desc, vendor="CNCF", model="Kubernetes 1.30")
        n += c
        for (name, typ, env, site, ip, vendor, model, serial, bought, warranty, eol, cost, inst) in HOSTS:
            cis[name], c = self._ci(
                tenant, name, ci_type=typ, environment=env, site=site, ip_address=ip, vendor=vendor, model=model,
                serial=serial, asset_tag=f"EX-AT-{zlib.crc32(name.encode()) % 9000 + 1000}" if serial else "",
                purchase_date=_days(-bought), warranty_end=_days(warranty), eol_date=_days(eol),
                cost=Decimal(cost) if cost else None, prometheus_instance=inst, owner="Infrastructure",
                description=f"{vendor} {model}".strip())
            n += c
        for svc in [s[0] for s in SERVICES]:
            dom = cis[svc].business_domain
            if dom in cis:
                n += Relationship.objects.get_or_create(source=cis[svc], target=cis[dom], rel_type="part_of",
                                                        defaults={"note": "Example"})[1]
        for s, rt, t, origin, conf in RELS:
            n += Relationship.objects.get_or_create(source=cis[s], target=cis[t], rel_type=rt,
                                                    defaults={"origin": origin, "confidence": conf, "note": "Example"})[1]
        sw_map = {}
        for name, version, vendor, cat, hosts in SOFTWARE:
            sw, c = Software.objects.get_or_create(tenant_key=tenant, name=name, version=version, defaults={
                "vendor": vendor, "category": cat, "description": f"{MARK}{name} {version}"})
            n += c
            if c:
                sw.installs.set([cis[h] for h in hosts])
            sw_map[name] = sw
        for product, vendor, sw, typ, seats, expiry, cost, ref in LICENSES:
            n += License.objects.get_or_create(tenant_key=tenant, product=product, defaults={
                "vendor": vendor, "software": sw_map.get(sw), "license_type": typ, "seats": seats, "expiry": _days(expiry),
                "cost": Decimal(cost), "reference": ref, "notes": MARK + "demo license record"})[1]
        return n
