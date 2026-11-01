"""Create clearly-marked example runbooks, rules and templates. Idempotent; never runs automatically.

* Runbooks carry the tag "example".
* Rules and templates have a description starting with "Example". Rules are created **disabled** so nothing
  reacts to real events until an operator reviews and enables them.
Nothing here fabricates monitoring data or executions.
"""
from django.conf import settings
from django.core.management.base import BaseCommand
from django.db import transaction

from automation.models import Rule, Runbook, Template

RUNBOOKS = [
    {
        "title": "Example – Web portal returns HTTP 5xx",
        "service": "Customer web portal", "ci_name": "web-portal-lb", "owner": "Application Support",
        "tags": "example, web, url-checker",
        "symptoms": "URL Checker reports the portal Down with HTTP 502/503.\nUsers see “Bad Gateway” or time-outs.",
        "steps": "1. Open the URL check and confirm the failure is current (Run check now).\n"
                 "2. Check the load balancer pool: are the backend members marked down?\n"
                 "   $ curl -sk -o /dev/null -w '%{http_code}' https://portal.example.net/health\n"
                 "3. Restart the application service on the failed backend node.\n"
                 "   $ sudo systemctl restart portal-app\n"
                 "4. Re-run the URL check. If it still fails after 10 minutes, raise the incident to P2 and page the "
                 "application on-call.\n"
                 "5. Record the cause and the fix in the incident timeline.",
    },
    {
        "title": "Example – TCP service port unreachable",
        "service": "Market data feed", "ci_name": "mdf-gw-01", "owner": "Network Operations",
        "tags": "example, network, tcp",
        "symptoms": "Telnet Monitoring shows the port Down (connection refused or timed out).",
        "steps": "1. Check whether the host answers ping and whether other ports on it are up.\n"
                 "2. Check the firewall policy and recent changes for the host and port.\n"
                 "3. Log in to the host and confirm the service is listening.\n"
                 "   $ ss -ltnp | grep :9601\n"
                 "4. Start the service if it is stopped and watch the next check result.\n"
                 "5. If the host itself is down, follow the server-down runbook and open a P1 incident.",
    },
    {
        "title": "Example – TLS certificate expiring",
        "service": "Public websites", "owner": "Security Operations", "tags": "example, tls, domains",
        "symptoms": "Domains › SSL Certificates shows the certificate Expiring (< 30 days) or Expired.",
        "steps": "1. Identify the certificate owner and the issuing CA from the SSL Certificates page.\n"
                 "2. Raise a change request for the renewal.\n"
                 "3. Renew the certificate and deploy it to every endpoint that serves the name.\n"
                 "4. Run Test SSL on the domain and confirm the new expiry date.",
    },
]

RULES = [
    {"name": "Example – Critical URL check opens P2 incident",
     "description": "Example rule (disabled): opens a P2 incident when a URL check goes Down.",
     "match_source": "urlchecker", "min_severity": "critical", "cooldown_minutes": 30,
     "action": "open_incident", "action_params": {"priority": "P2"}, "runbook": "Example – Web portal returns HTTP 5xx"},
    {"name": "Example – Restart service via StackStorm",
     "description": "Example rule (disabled): triggers a StackStorm webhook when a TCP check goes Down.",
     "match_source": "tcpcheck", "min_severity": "critical", "cooldown_minutes": 15,
     "action": "stackstorm", "action_params": {"trigger": "linkedeye_restart_service", "payload": {"action": "restart"}}},
    {"name": "Example – Link TLS runbook to certificate warnings",
     "description": "Example rule (disabled): links the TLS runbook to certificate warnings from Domains.",
     "match_source": "domainmonitor", "min_severity": "warning", "title_contains": "certificate", "cooldown_minutes": 1440,
     "action": "link_runbook", "action_params": {}, "runbook": "Example – TLS certificate expiring"},
]

TEMPLATES = [
    {"kind": "url_check", "name": "Example – HTTPS health endpoint",
     "description": "Example template: a 1-minute API check of a /health endpoint.",
     "fields": {"check_type": "api", "method": "GET", "expected_status": 200, "interval_seconds": 60, "timeout_seconds": 10,
                "degraded_ms": 800, "site": "All Sites", "tags": "example"}},
    {"kind": "tcp_check", "name": "Example – SSH port",
     "description": "Example template: TCP 22 that must answer with an SSH banner.",
     "fields": {"port": 22, "expect_banner": "SSH-", "interval_seconds": 300, "timeout_seconds": 5, "degraded_ms": 500,
                "site": "All Sites", "tags": "example"}},
    {"kind": "incident", "name": "Example – Planned maintenance overrun",
     "description": "Example template: P3 incident for a maintenance window that ran over.",
     "fields": {"title": "Planned maintenance overran its window", "priority": "P3",
                "description": "The maintenance window has ended but the work is not complete.\nImpact: \nNext update: "}},
    {"kind": "notification", "name": "Example – Trading day start check failed",
     "description": "Example template: warning notification for a failed start-of-day check.",
     "fields": {"title": "Start-of-day check failed", "severity": "warning",
                "message": "The start-of-day validation did not complete. Operations is investigating."}},
]


class Command(BaseCommand):
    help = "Create example runbooks, rules (disabled) and templates for the Automation module (idempotent)."

    def add_arguments(self, parser):
        parser.add_argument("--remove", action="store_true", help="Delete the example runbooks, rules and templates.")

    @transaction.atomic
    def handle(self, *args, remove=False, **opts):
        tenant = settings.LINKEDEYE_TENANT
        if remove:
            n1, _ = Rule.objects.filter(tenant_key=tenant, name__in=[r["name"] for r in RULES]).delete()
            n2, _ = Runbook.objects.filter(tenant_key=tenant, title__in=[r["title"] for r in RUNBOOKS]).delete()
            n3, _ = Template.objects.filter(tenant_key=tenant, name__in=[t["name"] for t in TEMPLATES]).delete()
            self.stdout.write(self.style.SUCCESS(f"Removed {n1} rule, {n2} runbook and {n3} template row(s)."))
            return
        made = {"runbooks": 0, "rules": 0, "templates": 0}
        books = {}
        for rb in RUNBOOKS:
            obj, created = Runbook.objects.get_or_create(tenant_key=tenant, title=rb["title"],
                                                         defaults={**{k: v for k, v in rb.items() if k != "title"},
                                                                   "created_by": "seed_automation"})
            books[obj.title] = obj
            made["runbooks"] += created
        for r in RULES:
            fields = {k: v for k, v in r.items() if k not in ("name", "runbook")}
            fields["runbook"] = books.get(r.get("runbook")) if r.get("runbook") else None
            _obj, created = Rule.objects.get_or_create(tenant_key=tenant, name=r["name"],
                                                       defaults={**fields, "enabled": False, "created_by": "seed_automation"})
            made["rules"] += created
        for t in TEMPLATES:
            _obj, created = Template.objects.get_or_create(tenant_key=tenant, name=t["name"],
                                                           defaults={"kind": t["kind"], "description": t["description"],
                                                                     "fields": t["fields"], "created_by": "seed_automation"})
            made["templates"] += created
        self.stdout.write(self.style.SUCCESS(
            f"Example automation data: {made['runbooks']} runbook(s), {made['rules']} rule(s) (disabled) and "
            f"{made['templates']} template(s) created; existing examples left unchanged."))
