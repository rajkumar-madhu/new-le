# Adding these apps to LinkedEyeWebProject

The `domainmonitor` app started from `LinkedEye_Domains_Integration_Patch`. Its `0001_initial` migration is
unchanged, so databases that already applied the patch upgrade in place with `0002`.

## What changed relative to the patch

| Change | Why |
|---|---|
| Hostname regex fixed (`\\.` → `\.` inside the raw string) | The patch regex required a literal backslash, so every real hostname (e.g. `nse.finspot.in`) failed validation. `0002` updates the validator. |
| Monitoring fields + `DomainCheck` history (migration `0002`) | Real DNS / HTTPS / TLS status instead of a permanent `Unknown`. |
| `default_auto_field = AutoField` on the app | Keeps the integer primary key the patch created; avoids rewriting the PK on an existing MySQL table. |
| Page moved to `/domains/` (Overview, Domain List, SSL) | `/configuration/domains/` now redirects there. |
| JSON API unchanged at `/configuration/domains/api/` | Same request/response contract; responses gain extra read-only fields (`status`, `ip`, `response_ms`, `ssl_expires_at`, `last_checked_at`). |

## Steps (staging first)

1. Copy `probes/`, `urlchecker/`, `domainmonitor/` and `core/templatetags/le.py` + `core/static/linkedeye/`
   (or the whole `core/` app if you adopt the console shell).
2. Add `"probes"`, `"urlchecker"`, `"domainmonitor"` (and `"core"`) to `INSTALLED_APPS`.
3. Add the `PROBE_*` and `LINKEDEYE_TENANT` settings from `linkedeye/settings.py`.
4. Mount URLs:
   ```python
   path("monitoring/url-checker/", include("urlchecker.urls")),
   path("domains/", include("domainmonitor.urls")),
   path("configuration/domains/", include(domainmonitor.urls.api_urlpatterns)),
   ```
5. `python manage.py migrate domainmonitor && python manage.py migrate urlchecker`
6. Run `python manage.py run_probes` as its own process (the existing `linkedeye-bod` container is a natural
   home, next to `urlchecker.py` / `telnet_checker.py`).

## Before production (carried over from the patch, still open)

* Replace the staff-only checks with the existing per-tenant RBAC and `lesites` site membership.
  `LINKEDEYE_TENANT` currently scopes the console to one tenant.
* Publish state changes to RabbitMQ (`bod_update` / `delta_update`) and Redis (`{site}:BOD_URLChecker`) so
  the BOD/EOD dashboard and StackStorm see URL and domain failures. `probes/runner.py` logs every state change
  (`linkedeye.probes` logger); that is the hook point.
* Audit create/update/delete through the existing `AuditlogsModel`.
* Rotate any secrets that were exposed in the original codebase and harden `SECRET_KEY`, `ALLOWED_HOSTS` and CORS.
