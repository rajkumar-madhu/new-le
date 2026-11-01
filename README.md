# LinkedEye console

The LinkedEye ITSM & monitoring console, as a Django project. It is built so its apps can also be dropped
into the existing **LinkedEyeWebProject** (Django 4.x); see [docs/INTEGRATION.md](docs/INTEGRATION.md).

Every page shows real data from the database or a configured integration. When an integration is not set up the
page says "Not connected" and names the setting; nothing is invented. Each module has an optional
`manage.py seed_<module>` command that adds clearly marked example records for demos.

| Area | URL | Data |
|---|---|---|
| Dashboard | `/` | Problems and KPIs across every module (URL, domain, device, TCP, alerts, incidents) |
| Service Desk | `/service-desk/…` | Incidents, problems, changes, requests, SLA policies, service catalog; incidents open automatically from critical events |
| Assets & CMDB, Heatmap | `/assets/…`, `/cmdb/…`, `/monitoring/heatmap/` | Configuration items, relationships, topology, software and licences; heatmap coloured from linked checks |
| Monitoring | `/monitoring/infrastructure/`, `/monitoring/nagios/`, `/monitoring/prometheus/`, `/monitoring/alerts/`, `/monitoring/metrics-explorer/` | Prometheus (node_exporter), Nagios Core and Alertmanager (`POST /api/v1/alertmanager/`, bearer token) |
| URL Checker | `/monitoring/url-checker/` | HTTP(S) checks: status, response time, expected text, TLS expiry, uptime, history, CSV |
| Telnet / TCP, Uptime | `/monitoring/telnet/`, `/monitoring/uptime/` | TCP reachability with optional banner; one uptime table for URL, TCP and domains with SLA targets |
| Network devices | `/network/…` | Device inventory per type, TCP reachability, interfaces via Prometheus snmp_exporter, discovery |
| Domains | `/domains/…` | DNS, availability, SSL, uptime, performance, security grading (A–F) and exports |
| Exporters, Logs & Events | `/monitoring/exporters/`, `/logs/`, `/logs/events/` | Exporter health scrapes, log ingest API (`POST /api/v1/logs/`, bearer token), unified event stream |
| BOD / EOD | `/bod-eod/` | Market-day checklists over URL/TCP/domain checks, manual sign-offs, IST scheduler, holidays |
| Automation | `/automation/…`, `/templates/` | Runbooks, StackStorm triggers, event-driven rules, templates |
| Reports & Analytics | `/reports/`, `/analytics/` | CSV reports, scheduled e-mail delivery, cross-module analytics |
| Administration | `/administration/` | Users and site roles, sites, audit log, integrations with test buttons, system health |
| Domains JSON API (integration-patch contract) | `/configuration/domains/api/` | Staff only |

The original design mock-ups with sample data are kept under `/legacy/` for comparison.

## Run locally

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
```

```bash
export LINKEDEYE_DEBUG=true
```

```bash
.venv/bin/python manage.py migrate && .venv/bin/python manage.py createsuperuser
```

```bash
.venv/bin/python manage.py seed_examples   # optional: example URLs and domains, tagged "example"
# optional per module: seed_servicedesk, seed_cmdb, seed_network, seed_telemetry, seed_tcpcheck, seed_observe,
# seed_bodeod, seed_automation, seed_administration, seed_domainmonitor
```

```bash
.venv/bin/python manage.py run_probes      # scheduler; leave running (Ctrl+C to stop)
```

```bash
.venv/bin/python manage.py runserver
```

Open http://127.0.0.1:8000 and sign in. Access comes from site memberships (Administration → Users): a
**viewer** reads, an **operator** also runs checks and works tickets, an **admin** also manages configuration
and users. A role can cover one site or all sites. Users without memberships fall back to viewer (or operator
for staff). Sign-ins, sign-outs and every change are recorded in the audit log.

## How checks run

* `run_probes` is the worker: it runs the URL and domain probes and every job the modules register (TCP checks,
  device reachability, exporter scrapes, BOD/EOD scheduler, scheduled reports, heartbeat, retention). Keep one
  running; Administration → System health shows its heartbeat.
* It wakes every 15 s, runs every check whose interval has elapsed (thread pool,
  `LINKEDEYE_PROBE_WORKERS`), stores a result row and updates the latest status on the check.
  `--once` runs a single pass (use it from cron instead of the loop if you prefer).
* Saving a check in the UI, **Run Check Now** and the domain quick actions run immediately.
* URL status: **Down** = connection/TLS/DNS error, unexpected status code, or expected text missing;
  **Degraded** = slower than the check's threshold (default 1000 ms) or certificate expiring in < 15 days;
  otherwise **Online**. Uptime counts Degraded as available.
* Domain status: DNS `Resolved/Failed`, availability `Up` (any HTTPS response below 500) / `Down`,
  SSL `Valid` / `Expiring` (< 30 days) / `Expired` / `Invalid` / `Unreachable`.
* Results older than `LINKEDEYE_PROBE_RETENTION_DAYS` (30) are pruned hourly.

### Probe safety (SSRF)

Targets are resolved first and each address is checked **before** connecting; the connection then goes to
that validated address (Host header and TLS SNI still use the hostname), so DNS answers cannot be switched
in between. Every redirect hop is checked again.

* Always refused: link-local (incl. `169.254.169.254` cloud metadata), multicast, `0.0.0.0/8`, reserved.
* Loopback and private ranges are refused unless listed in `LINKEDEYE_PROBE_ALLOWED_PRIVATE_CIDRS`,
  e.g. `10.10.0.0/16,10.20.0.0/16` for internal NSE/BSE services.
* Probes connect directly and do not use `HTTP(S)_PROXY`.

## Configuration

All settings come from environment variables; see [.env.example](.env.example). Production needs at least
`LINKEDEYE_SECRET_KEY`, `LINKEDEYE_ALLOWED_HOSTS` and `LINKEDEYE_CSRF_TRUSTED_ORIGINS`. MySQL is supported
through `LINKEDEYE_DB_*` (install `mysqlclient`).

## Tests

```bash
LINKEDEYE_DEBUG=true .venv/bin/python manage.py test
```

Covers the SSRF policy (including a redirect into the metadata range), HTTP checks against a local server,
status evaluation, the domain runner, page rendering, permissions, and the integration-patch API contract.

## Layout

Full map, module layout and data flow: [docs/STRUCTURE.md](docs/STRUCTURE.md).

```
linkedeye/       settings (env-driven), urls
core/            platform: sites & roles, audit, events, notifications, jobs, Prometheus client, shell UI, charts
probes/          DNS / HTTP(S) / TLS checks with SSRF guard, runner, run_probes worker
urlchecker/      Monitoring › URL Checker
domainmonitor/   Domains (from LinkedEye_Domains_Integration_Patch, extended), patch JSON API
servicedesk/     incidents, problems, changes, requests, SLA, service catalog
cmdb/            assets, software, licenses, lifecycle, CIs, relationships, topology, heatmap
network/         switches, routers, firewalls, load balancers, wireless, servers, VMs, discovery
telemetry/       infrastructure, Nagios, Prometheus, alerts (Alertmanager webhook), metrics explorer
observe/         exporters, logs & events, log ingest API
tcpcheck/        Telnet/TCP checks, unified uptime
bodeod/          BOD / EOD market-day validation
automation/      runbooks, StackStorm, event workflows, templates
administration/  users & roles, sites, audit log, integrations, system health
reports/         report library (CSV, preview, scheduled e-mail) and cross-module analytics
docs/            structure, module contract, integration, deployment
```
