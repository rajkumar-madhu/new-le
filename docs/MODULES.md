# Module contract

Every LinkedEye module is a Django app that owns its directory. Shared code lives in `core/`, `probes/`,
`urlchecker/` and `domainmonitor/`; modules use it but do not edit it.

## Wiring (already done for each module)

* App listed in `INSTALLED_APPS`; root `urls.py` includes `"<app>.urls"` at `""`, so **the app's `urls.py`
  declares full paths** (e.g. `path("service-desk/incidents/", ...)`) with `app_name = "<app>"`.
* Sidebar entries (core/nav.py) point at URL names; a name that does not resolve yet falls back to a
  placeholder page. Required URL names per module are listed below.
* Page CSS: `<app>/static/<app>/page.css`, linked from templates with
  `{% block page_css %}<link rel="stylesheet" href="{% static '<app>/page.css' %}">{% endblock %}`.
  Scope rules under a wrapper class, e.g. `<div class="pg-<app>">`.

## Shared platform API

| Need | Use |
|---|---|
| Permission check | `from core.access import can, require, visible_sites, scope_by_site, role_for`. Perms: `view`, `operate` (run, acknowledge, add/edit records), `configure` (same rank as operate), `admin` (delete, settings, users). Decorate views with `@require("operate")`; in templates use `{% if perms_operate %}` – the base context provides `le_can` (see below). |
| Site scoping | Records store the site **name** in a `site` CharField (`"All Sites"` = global). Filter querysets with `scope_by_site(qs, request.user, field="site")`. Sites live in `core.models.Site` (name, code, region, timezone, criticality). |
| Audit | `from core.audit import audit`; call `audit(request, "create"|"update"|"delete"|"run"|..., obj, **details)` after every mutation. |
| Events | `from core.events import emit, event_emitted`; `emit(source="<app>", title=..., severity="critical"|"warning"|"info"|"ok", message=..., site=..., obj=..., fingerprint="<app>:<pk>", **data)` on every state change. Listen with `@receiver(event_emitted)` (args: `sender, event`). Never raise from a listener. |
| Periodic jobs | `from core.jobs import register`; in `AppConfig.ready()` call `register("<app>.<job>", interval_seconds, func)`; `manage.py run_probes` runs them. Jobs must be idempotent, bounded (timeouts) and must not raise. |
| Prometheus | `from core import prometheus`; `prometheus.configured()`, `query(promql)`, `query_range(promql, seconds, step)`, `targets()`, `alerts()`; errors raise `prometheus.PrometheusError` (show its message, never a stack trace). |
| Network probes | `from probes import checks`; `checks.http_check(url, ...)`, `checks.dns_check(host)`, `checks.tls_check(host, port)`, `checks.resolve_allowed(host, port)` (SSRF policy), `checks.check_address(ip)`. Any new socket code must go through `resolve_allowed` / `check_address`. |
| Notifications | Automatic for critical/warning events (core/notify.py); nothing to do. |
| Tenant | `settings.LINKEDEYE_TENANT`; models carry `tenant_key` where data could belong to more than one customer. |

`base.html` context: `le_can` is not provided yet – use `core.access.can(request.user, "operate")` in the view
and pass a boolean (e.g. `can_operate`) to the template.

## UI kit (core/static/linkedeye/app.css, core/templatetags/le.py, charts.js)

KPI cards (`.kpi.stacked > .kpi-top > .tile.s-* + .kpi-body`), panels (`.panel`, `.panel-h`), grids (`.grid .g-2
.g-3 .g-4 .g-main .g-charts`), tables (`.table-wrap > table`, `th.cb`/`td.cb`, `.row-actions`), chips
(`.chip.ok|warn|crit|purple|mute|teal`), `{% badge status %}`, `{% icon name %}`, `{% ficon name %}`,
`{% delta value good="up|down" %}`, tabs (`nav.tabs > a.on`), pager (`{% include "core/_pager.html" %}` with
`page` + `query`), charts (`div.chart[data-chart=line|bars|donut|spark][data-src]` + `json_script`),
`.empty` for empty states, `.messages` via Django messages. Forms: `.form-grid > .field` with labels.
Follow the existing pages (urlchecker/templates/urlchecker/index.html, domainmonitor/templates/…) for markup.

## Data rules

* Pages show **real data from the database or a configured integration**. When an integration is not
  configured, show a clear "not connected" state naming the setting to set; never fabricate numbers.
* Each module may ship `manage.py seed_<app>` that creates clearly-marked example records (description or tag
  "example") for demos. It must be idempotent and never run automatically.
* Every list view: search/filter where useful, pagination (`?per=`), CSV export where useful.
* Every mutation: POST + CSRF, permission check, `audit(...)`, success message, redirect.

## Cross-module interfaces

Modules may depend on each other only through these names, imported lazily inside functions
(`from django.apps import apps; M = apps.get_model("servicedesk", "Ticket")`) and guarded so the caller still
works if the other module is absent.

| Provider | Interface |
|---|---|
| servicedesk | `servicedesk.services.open_incident(title, description="", priority="P3", site="", source="", fingerprint="", ci_name="") -> Ticket` (dedupes open incidents by fingerprint); `servicedesk.services.resolve_by_fingerprint(fingerprint, note="")`. Model `Ticket` (kind: incident/problem/change/request; number like INC-1287; status; priority P1-P4; site). |
| cmdb | Model `ConfigurationItem` (name, ci_type, site, status, environment, owner, business_domain, attributes JSON). `cmdb.services.find_ci(name)`. |
| network | Model `Device` (name, device_type: switch/router/firewall/load_balancer/wireless/physical_server/virtual_machine, vendor, model, mgmt_ip, site, status: up/down/unknown, last_seen). |
| tcpcheck | Model `TcpCheck` (name, host, port, site, last_status: online/down/unknown, last_checked_at, last_response_ms). |
| automation | `automation.services.trigger_stackstorm(trigger, payload) -> Execution`. |
| urlchecker / domainmonitor | Existing models `UrlCheck`, `UrlResult`, `Domain`, `DomainCheck` (read-only for other modules). |
