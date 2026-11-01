# LinkedEye console

The LinkedEye ITSM & monitoring console, as a Django project. It is built so its apps can also be dropped
into the existing **LinkedEyeWebProject** (Django 4.x); see [docs/INTEGRATION.md](docs/INTEGRATION.md).

| Area | URL | Data |
|---|---|---|
| Dashboard | `/` | Real: problems across URL checks and domains |
| URL Checker | `/monitoring/url-checker/` | **Real** HTTP(S) checks: status code, response time, expected text, TLS expiry, uptime, 24 h trend, 7-day history, CSV export |
| Domains: Overview / Domain List / SSL Certificates | `/domains/`, `/domains/list/`, `/domains/ssl/` | **Real** DNS resolution, HTTPS availability and certificate expiry; quick actions Test DNS / Test SSL / Check Uptime |
| Domains JSON API (integration-patch contract) | `/configuration/domains/api/` | Real, staff-only |
| Heatmap | `/monitoring/heatmap/` | Sample data (Prometheus/Nagios not connected yet) |
| All Exporters, Logs & Events | `/monitoring/exporters/` | Sample data (exporter inventory/log pipeline not connected) |
| Incidents | `/service-desk/incidents/` | Sample data (Redmine not connected) |
| FortiGate FG-01 | `/network/firewalls/fg-01/` | Sample data (SNMP/FortiOS API not connected) |

Pages with sample data carry a **Sample data** label. Menu items that are not built yet open a placeholder page
rather than a dead link.

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
```

```bash
.venv/bin/python manage.py run_probes      # scheduler; leave running (Ctrl+C to stop)
```

```bash
.venv/bin/python manage.py runserver
```

Open http://127.0.0.1:8000 and sign in. Viewers can read everything; **staff** users can add, edit, delete and
run checks.

## How checks run

* `run_probes` wakes every 15 s, runs every check whose interval has elapsed (thread pool,
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

```
linkedeye/      settings (env-driven), urls
core/           shell (sidebar, header, login), dashboard, search, sample-data pages, icons, CSS, SVG charts
probes/         DNS / HTTP(S) / TLS checks with SSRF guard, runner, run_probes command, tests
urlchecker/     URL Checker models, views, templates
domainmonitor/  Domains (from LinkedEye_Domains_Integration_Patch, extended), patch JSON API
docs/           integration and deployment notes
```
