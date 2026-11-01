# Deploying LinkedEye

LinkedEye ships as one container image that runs in two roles against one database:

| Role | Command | Replicas | Notes |
|---|---|---|---|
| **web** | `gunicorn --config /app/gunicorn.conf.py` (image default) | 2 or more | Stateless. Serves the console, `/healthz`, the Alertmanager and log-ingest APIs, and `/static/`. |
| **probes** | `python manage.py run_probes` | **exactly 1** | The scheduler: URL / domain / TCP checks and every periodic job (SLA timers, BOD/EOD auto-runs, scheduled reports, retention, heartbeat). |
| **migrate** | `python manage.py migrate --noinput` | one-shot | Runs before web and probes start, once per release. |
| **db** | PostgreSQL 16 (MySQL 8 and SQLite also work) | 1 | The only state. Back it up (see [Backups](#backups)). |

Two ready-made layouts:

* [Docker Compose](#docker-compose) for a single host: `docker-compose.yml`, `deploy/compose.env.example`, optional
  Prometheus / Alertmanager / node-exporter under `deploy/prometheus/` and `deploy/alertmanager/`.
* [Kubernetes](#kubernetes): `deploy/kubernetes/` (kustomize).

## The probe scheduler runs exactly once

`run_probes` must run as **one process per database, never more**. Two schedulers would check every target
twice, emit duplicate events and notifications, race on incident creation and double-run BOD/EOD validations
and scheduled reports. The bundles enforce this:

* Compose: `probes` declares `deploy.replicas: 1`. Do not `docker compose up --scale probes=2`, and do not
  start a second stack (or a `run_probes` on a VM) against the same database.
* Kubernetes: `linkedeye-probes` has `replicas: 1` and `strategy: Recreate`, so a rollout stops the old pod
  before the new one starts. Never attach an HPA to it and never add a PodDisruptionBudget (with one replica
  it would block node drains; a drain simply restarts the pod).
* The scheduler writes a heartbeat (`administration.Heartbeat`, key `scheduler`) every 60 s with its host
  name. Its health check fails when the heartbeat is older than 5 minutes **or was written by another host**,
  so a second scheduler shows up as an unhealthy container. **Administration → System health** shows the same
  heartbeat.

Place the probes container where it can reach the targets you monitor. Private and loopback targets are
refused unless their range is listed in `LINKEDEYE_PROBE_ALLOWED_PRIVATE_CIDRS`; link-local and cloud-metadata
addresses are always refused.

## The image

```bash
docker build -t registry.example.com/linkedeye:9.0 .                               # PostgreSQL driver (default)
docker build --build-arg DB_EXTRAS="postgres mysql" -t registry.example.com/linkedeye:9.0 .   # + mysqlclient
docker build --build-arg DB_EXTRAS="" -t linkedeye:9.0-sqlite .                     # SQLite only
docker push registry.example.com/linkedeye:9.0
```

| Build argument | Default | Purpose |
|---|---|---|
| `DB_EXTRAS` | `postgres` | Space-separated list of `requirements-<name>.txt` extras: `postgres` (psycopg 3 binary, no system libraries), `mysql` (mysqlclient; compiled in the build stage, `libmariadb3` at runtime). |
| `PYTHON_VERSION` | `3.12` | Base image `python:<version>-slim`. |
| `VERSION`, `REVISION` | `9.0`, empty | OCI labels (`org.opencontainers.image.version` / `.revision`). |

Behind a TLS-intercepting proxy give pip your CA bundle as a build secret (never baked into a layer):
`docker build --secret id=pip_ca,src=/etc/ssl/certs/corp-bundle.pem ...`

What the image does:

* Multi-stage: dependencies are installed into `/opt/venv` in a build stage; the runtime stage has no compiler.
* Runs as the unprivileged user `linkedeye` (**uid/gid 10001**). Application files are owned by root and
  read-only; byte-code is compiled at build time, so a read-only root filesystem works. `/app/data` is the only
  writable directory (for an SQLite file in single-host trials).
* `collectstatic` runs at build time with a throwaway `LINKEDEYE_SECRET_KEY` that exists only for that build
  step. Static files are served by **WhiteNoise**: through `whitenoise.middleware.WhiteNoiseMiddleware` when it
  is in `settings.MIDDLEWARE` (hashed file names, compressed, cached for a year), otherwise through the WSGI
  wrapper `deploy/docker/container_wsgi.py` that gunicorn loads (5-minute cache). No separate web server is
  needed for `/static/`.
* `HEALTHCHECK`: `python /app/deploy/docker/healthcheck.py web` requests `GET /healthz` from the local gunicorn
  with a `Host` header taken from `LINKEDEYE_ALLOWED_HOSTS`. `/healthz` is public and checks the database
  connection. `healthcheck.py probes` checks the scheduler heartbeat (above).
* gunicorn settings come from `gunicorn.conf.py` and can be changed with `GUNICORN_*` variables
  ([table](#process-and-container-variables)). Defaults: gthread workers, `2 × CPU limit + 1` processes (max 8),
  4 threads each, 60 s timeout, access log on stdout without successful `/healthz` lines.

The container prints logs to stdout/stderr only; collect them with your platform's log driver.

## Docker Compose

Prerequisites: Docker Engine 24+ with the Compose plugin (v2.24+), a DNS name for the console and a TLS
certificate on the reverse proxy in front of it.

```bash
cp deploy/compose.env.example .env
# edit .env: LINKEDEYE_SECRET_KEY, LINKEDEYE_DB_PASSWORD, LINKEDEYE_ALLOWED_HOSTS, LINKEDEYE_CSRF_TRUSTED_ORIGINS
python3 -c "import secrets; print(secrets.token_urlsafe(50))"     # a value for LINKEDEYE_SECRET_KEY
chmod 600 .env
docker compose build
docker compose up -d
docker compose ps                     # db, web and probes "healthy"; migrate "exited (0)"
docker compose exec web python manage.py createsuperuser
docker compose exec web python manage.py bootstrap_sites          # optional: site list
```

Compose refuses to start while `LINKEDEYE_SECRET_KEY` or `LINKEDEYE_DB_PASSWORD` is empty.

Services:

| Service | Image | Health check | Data |
|---|---|---|---|
| `db` | `postgres:16-alpine` | `pg_isready` | volume `pgdata` |
| `migrate` | LinkedEye | (one-shot; web and probes wait for it to exit 0) | |
| `web` | LinkedEye | `healthcheck.py web` → `/healthz` | none |
| `probes` | LinkedEye | `healthcheck.py probes` → heartbeat | none |
| `prometheus` *(profile observability)* | `prom/prometheus:v3.1.0` | `/-/healthy` | volume `prometheus-data` |
| `alertmanager` *(profile observability)* | `prom/alertmanager:v0.28.0` | `/-/healthy` | volume `alertmanager-data` |
| `node-exporter` *(profile observability)* | `prom/node-exporter:v1.8.2` | `/metrics` | reads the host via `/host` |

The LinkedEye containers run with a read-only root filesystem, `/tmp` on tmpfs, all capabilities dropped and
`no-new-privileges`. Logs rotate at 10 MB × 5 files per container.

**TLS and the published port.** `web` is published on `WEB_PUBLISH` (default `127.0.0.1:8000`, host-local only).
Terminate TLS in a reverse proxy on the host (nginx, Caddy, HAProxy, a load balancer) that forwards to
`127.0.0.1:8000` and sets `X-Forwarded-Proto: https`; set `GUNICORN_FORWARDED_ALLOW_IPS` to the proxy's address
as seen from the container (the Docker bridge gateway, e.g. `172.18.0.1`) so Django knows requests were HTTPS.
Session and CSRF cookies are `Secure` when `LINKEDEYE_DEBUG=false`, so over plain HTTP sign-in only works on
`http://localhost:8000` (browsers treat localhost as secure); on any other host name use HTTPS.

Minimal nginx server block:

```nginx
server {
    listen 443 ssl http2;
    server_name linkedeye.example.internal;
    ssl_certificate     /etc/ssl/linkedeye/fullchain.pem;
    ssl_certificate_key /etc/ssl/linkedeye/privkey.pem;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    client_max_body_size 2m;
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 90s;     # "Run check now" probes the target inside the request
    }
}
```

**Using an external database.** Set `LINKEDEYE_DB_ENGINE`, `LINKEDEYE_DB_HOST`, `LINKEDEYE_DB_PORT`,
`LINKEDEYE_DB_NAME`, `LINKEDEYE_DB_USER`, `LINKEDEYE_DB_PASSWORD` in `.env` and start only the application
services, migrations first (`--no-deps` also skips the "wait for migrate" ordering, so run it on its own):

```bash
docker compose run --rm --no-deps migrate && docker compose up -d --no-deps web probes
```

For MySQL build with `LINKEDEYE_DB_EXTRAS="postgres mysql"` in `.env`.

### Observability profile

```bash
# .env: LINKEDEYE_ALERTMANAGER_WEBHOOK_TOKEN=<random>   and   LINKEDEYE_PROMETHEUS_URL=http://prometheus:9090
docker compose --profile observability up -d
docker compose up -d web probes        # pick up LINKEDEYE_PROMETHEUS_URL if you added it after the first start
```

* `deploy/prometheus/prometheus.yml` scrapes Prometheus, Alertmanager and node-exporter (labelled
  `site: "All Sites"`) and loads `deploy/prometheus/rules/*.yml` (starter rules: target down, filesystem
  almost full, memory pressure, sustained CPU). Add your exporters under `scrape_configs` with a `site` label
  that matches a LinkedEye site name, then `docker compose restart prometheus`.
* `deploy/alertmanager/alertmanager.yml` sends every alert to `http://web:8000/api/v1/alertmanager/` with
  `Authorization: Bearer <token>`. The token is read from `/run/secrets/alertmanager_webhook_token`, which
  compose creates from `LINKEDEYE_ALERTMANAGER_WEBHOOK_TOKEN`, the same variable the console checks. The host
  name `web` must be in `LINKEDEYE_ALLOWED_HOSTS` (it is in the example file). While the token is empty compose
  mounts no token file, so the `alertmanager` container reports **unhealthy** instead of silently failing every
  notification. Compose copies the token into the container only when it is (re)created: after changing it run
  `docker compose --profile observability up -d --force-recreate web alertmanager`.
* Prometheus and Alertmanager have no authentication; their ports are published on `127.0.0.1` only
  (`PROMETHEUS_PUBLISH`, `ALERTMANAGER_PUBLISH`).
* With `LINKEDEYE_PROMETHEUS_URL=http://prometheus:9090` the console's Prometheus, metrics explorer, heatmap and
  infrastructure pages read from it; without it they show "not connected".

### Day-2 operations (Compose)

```bash
docker compose logs -f web probes                     # logs
docker compose exec web python manage.py shell        # Django shell
docker compose exec probes python /app/deploy/docker/healthcheck.py probes
docker compose restart probes                         # restart the scheduler (finishes the current pass first)
```

## Kubernetes

Prerequisites: Kubernetes 1.27+, an ingress controller, a CNI that enforces NetworkPolicy (for the policies to
have effect), PostgreSQL 16 reachable from the cluster (managed service, an operator such as CloudNativePG, or
your own StatefulSet), and the image pushed to a registry the cluster can pull from.

| File | Contents |
|---|---|
| `namespace.yaml` | Namespace `fs-linkedeye` with Pod Security Admission `restricted` enforced. |
| `serviceaccount.yaml` | ServiceAccount `linkedeye`, no API token mounted. |
| `configmap.yaml` | `linkedeye-config`: every non-secret `LINKEDEYE_*` setting. |
| `secret.template.yaml` | `linkedeye-secrets` with **placeholders only**; not part of the kustomization. |
| `migrate-job.yaml` | Job `linkedeye-migrate`: `manage.py migrate`. |
| `web-deployment.yaml` | Deployment `linkedeye-web` (2 replicas, rolling update with no unavailable pods, startup/readiness/liveness on `/healthz`, resources, non-root read-only containers, spread over nodes) and PodDisruptionBudget (`minAvailable: 1`). |
| `probes-deployment.yaml` | Deployment `linkedeye-probes` (**replicas 1, strategy Recreate**), liveness = scheduler heartbeat. |
| `service.yaml` | ClusterIP Service `linkedeye-web:8000`. |
| `ingress.yaml` | Ingress for `linkedeye.example.com` with TLS Secret `linkedeye-tls` (placeholders). |
| `networkpolicy.yaml` | Default-deny ingress; ingress controller (and optional in-cluster Alertmanager) → web:8000; web / probes / migrate → database:5432. |
| `kustomization.yaml` | Ties it together; sets the image. |
| `optional/backup-cronjob.yaml` | Not applied by default: nightly `pg_dump` CronJob + PVC (see [Backups](#backups)). |

### First installation

1. **Edit the placeholders** (everything marked `REPLACE`):
   * `kustomization.yaml`: `images[0].newName` / `newTag` (or a `digest`).
   * `configmap.yaml`: `LINKEDEYE_ALLOWED_HOSTS` and `LINKEDEYE_CSRF_TRUSTED_ORIGINS` (your host name; keep the
     `linkedeye-web…` service names, the kubelet probes and in-cluster Alertmanager use them),
     `LINKEDEYE_DB_HOST`, `LINKEDEYE_PROBE_ALLOWED_PRIVATE_CIDRS`, integrations.
   * `ingress.yaml`: host, `ingressClassName`, TLS secret / cert-manager issuer.
   * `networkpolicy.yaml`: the ingress controller's namespace and pod labels, the monitoring namespace (or delete
     that rule), and the labels of your PostgreSQL pods if they run in `fs-linkedeye`.
2. **Create the namespace and Secret** (nothing secret goes into git):

   ```bash
   kubectl apply -f deploy/kubernetes/namespace.yaml
   kubectl -n fs-linkedeye create secret generic linkedeye-secrets \
     --from-literal=LINKEDEYE_SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(50))')" \
     --from-literal=LINKEDEYE_DB_PASSWORD='<database password>' \
     --from-literal=LINKEDEYE_ALERTMANAGER_WEBHOOK_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
   kubectl -n fs-linkedeye create secret tls linkedeye-tls --cert=fullchain.pem --key=privkey.pem   # unless cert-manager issues it
   ```

   Or fill a copy of `secret.template.yaml` outside the repository, or have Sealed Secrets / External Secrets
   produce a Secret named `linkedeye-secrets` with those keys. Only add keys you use: a key that is present
   enables its integration with that value.
3. **Apply and wait:**

   ```bash
   kubectl apply -k deploy/kubernetes
   kubectl -n fs-linkedeye wait --for=condition=complete job/linkedeye-migrate --timeout=15m
   kubectl -n fs-linkedeye rollout status deploy/linkedeye-web deploy/linkedeye-probes
   kubectl -n fs-linkedeye exec -it deploy/linkedeye-web -- python manage.py createsuperuser
   ```

Web and probes pods start with an init container that loops on `manage.py migrate --check` until the
migration Job has applied every migration the image contains, so new code never runs against an old schema.
That init container, the migration Job and gunicorn first run `healthcheck.py preflight`, which refuses to
start while any `LINKEDEYE_*` value still contains a `<REPLACE ...>` placeholder from `secret.template.yaml`
(an unedited template would otherwise make the published placeholder your signing key or webhook token).

### Health checks and security (Kubernetes)

* web: `startupProbe` (up to 2 min), `readinessProbe` (every 10 s) and `livenessProbe` (every 20 s, 6
  failures) all `GET /healthz` with `Host: linkedeye-web`. A database outage takes pods out of the Service
  quickly but restarts them only after two minutes.
* probes: exec `healthcheck.py probes` (startup up to 5 min, then every 60 s, 3 failures). Tune with
  `HEALTHCHECK_MAX_HEARTBEAT_AGE` (seconds, default 300).
* All pods: `runAsNonRoot` (uid 10001), `readOnlyRootFilesystem`, no privilege escalation, all capabilities
  dropped, `RuntimeDefault` seccomp, no service-account token, `/tmp` as a 64 Mi memory `emptyDir`. They pass
  Pod Security Admission `restricted`.
* gunicorn trusts `X-Forwarded-Proto` from any peer (`GUNICORN_FORWARDED_ALLOW_IPS="*"`) because the
  NetworkPolicy lets only the ingress controller reach the web pods. If you drop the NetworkPolicy, set it to
  the controller's pod CIDR.
* Egress is not restricted: probes (and "Run check now" in the web tier) connect to whatever you monitor. The
  application-level SSRF guard applies.
* In-cluster Alertmanager: point a webhook receiver at
  `http://linkedeye-web.fs-linkedeye.svc:8000/api/v1/alertmanager/` with `http_config.authorization`
  (`type: Bearer`, `credentials_file` from a Secret holding the same token), and allow its namespace in
  `networkpolicy.yaml`.

Sizing defaults: web 250m / 384 Mi requested, 1 CPU / 1 Gi limit, 3 workers × 4 threads per pod; probes 200m /
256 Mi requested, 768 Mi limit. Raise `LINKEDEYE_PROBE_WORKERS` and the probes CPU limit together when you
monitor many targets.

## Environment variables

Every setting is an environment variable read at start-up (`linkedeye/settings.py`). Restart web and probes
after a change (compose: `docker compose up -d`; Kubernetes: `kubectl -n fs-linkedeye rollout restart deploy`).

> A variable that is set to an empty string replaces the default with `""`; for numeric settings that is a
> start-up error. Leave optional variables out (or comment them) rather than setting them to nothing.

### Application (`LINKEDEYE_*`)

| Variable | Default | Secret | Description |
|---|---|---|---|
| `LINKEDEYE_SECRET_KEY` | none (**required** unless DEBUG) | yes | Django signing key: 50+ random characters. Changing it signs everyone out. |
| `LINKEDEYE_DEBUG` | `false` | | `true` only for local development (also makes cookies non-Secure and e-mail print to the console). Never in production. |
| `LINKEDEYE_ALLOWED_HOSTS` | `localhost,127.0.0.1` with DEBUG, else empty (**required**) | | Comma-separated host names the console answers to. Include the public name and the names health checks / Alertmanager use (`web` in compose, `linkedeye-web…` in Kubernetes). A leading dot matches subdomains. |
| `LINKEDEYE_CSRF_TRUSTED_ORIGINS` | empty | | Comma-separated origins with scheme, e.g. `https://linkedeye.example.com`. Required behind HTTPS. |
| `LINKEDEYE_DB_ENGINE` | `django.db.backends.sqlite3` | | `django.db.backends.postgresql` (compose and Kubernetes default) or `django.db.backends.mysql`. |
| `LINKEDEYE_DB_NAME` | `<project>/db.sqlite3` | | Database name (file path for SQLite; use `/app/data/…` in the container). |
| `LINKEDEYE_DB_USER` | empty | | Database user. |
| `LINKEDEYE_DB_PASSWORD` | empty | yes | Database password. |
| `LINKEDEYE_DB_HOST` | empty | | Database host (`db` in compose). |
| `LINKEDEYE_DB_PORT` | empty (driver default) | | `5432` PostgreSQL, `3306` MySQL. |
| `LINKEDEYE_DB_CONN_MAX_AGE` | `60` | | Seconds a database connection is reused (`0` = close after each request). Connections are health-checked before reuse. |
| `LINKEDEYE_TIME_ZONE` | `Asia/Kolkata` | | Display time zone (IANA name). Data is stored in UTC. |
| `LINKEDEYE_TENANT` | `default` | | Tenant whose records this deployment shows (single-tenant deployment). |
| `LINKEDEYE_LOG_LEVEL` | `INFO` | | Level of the `linkedeye.*` loggers (probes, jobs, integrations). |
| `LINKEDEYE_PROBE_ALLOWED_PRIVATE_CIDRS` | empty | | Comma-separated private / loopback ranges probes may connect to, e.g. `10.10.0.0/16,10.20.0.0/16`. Everything private not listed is refused. |
| `LINKEDEYE_PROBE_TIMEOUT` | `10` | | Seconds per probe step (connect, TLS, response). |
| `LINKEDEYE_PROBE_WORKERS` | `8` | | Parallel probe threads in `run_probes`. |
| `LINKEDEYE_PROBE_RETENTION_DAYS` | `30` | | Days of URL / domain check results kept (pruned hourly). |
| `LINKEDEYE_NOTIFY_WEBHOOK_URLS` | empty | yes (URLs often embed tokens) | Comma-separated URLs that receive a JSON POST per notified event (Slack, Teams, Apprise, StackStorm, …). |
| `LINKEDEYE_NOTIFY_EMAILS` | empty | | Comma-separated recipients of event e-mails. |
| `LINKEDEYE_NOTIFY_SEVERITIES` | `critical,warning` | | Event severities that notify. |
| `LINKEDEYE_EMAIL_BACKEND` | SMTP (console backend with DEBUG) | | Django e-mail backend class path. |
| `LINKEDEYE_EMAIL_HOST` | `localhost` | | SMTP server. |
| `LINKEDEYE_EMAIL_PORT` | `25` | | SMTP port. |
| `LINKEDEYE_EMAIL_HOST_USER` | empty | | SMTP user. |
| `LINKEDEYE_EMAIL_HOST_PASSWORD` | empty | yes | SMTP password. |
| `LINKEDEYE_EMAIL_USE_TLS` | `false` | | STARTTLS to the SMTP server. |
| `LINKEDEYE_DEFAULT_FROM_EMAIL` | `linkedeye@localhost` | | Sender address. |
| `LINKEDEYE_PROMETHEUS_URL` | empty (not connected) | | Prometheus base URL, e.g. `http://prometheus:9090`. Queried server-side only. |
| `LINKEDEYE_PROMETHEUS_TIMEOUT` | `8` | | Seconds per Prometheus API call. |
| `LINKEDEYE_ALERTMANAGER_WEBHOOK_TOKEN` | empty (webhook answers 503) | yes | Bearer token Alertmanager must send to `POST /api/v1/alertmanager/`. |
| `LINKEDEYE_LOG_INGEST_TOKEN` | empty (endpoint disabled) | yes | Bearer token for `POST /api/v1/logs/`. |
| `LINKEDEYE_STACKSTORM_URL` | empty (not connected) | | StackStorm webhook base, e.g. `https://st2.example/api/v1/webhooks/`. |
| `LINKEDEYE_STACKSTORM_API_KEY` | empty | yes | StackStorm API key. |
| `LINKEDEYE_INCIDENT_AUTO_CREATE` | `true` | | Open incidents automatically for critical events / alerts. |
| `LINKEDEYE_NAGIOS_URL` | empty (not connected) | | Nagios CGI base (`…/nagios/cgi-bin` or the `statusjson.cgi` URL). |
| `LINKEDEYE_NAGIOS_USER` | empty | | Nagios CGI user. |
| `LINKEDEYE_NAGIOS_PASSWORD` | empty | yes | Nagios CGI password. |
| `LINKEDEYE_NAGIOS_TIMEOUT` | `10` | | Seconds per Nagios request (clamped to 1–60). |
| `LINKEDEYE_LOG_RETENTION_DAYS` | `14` | | Days of ingested log entries kept (Logs & Events). |
| `LINKEDEYE_TELEMETRY_ALERT_RETENTION_DAYS` | `90` | | Days resolved Alertmanager alerts are kept. |
| `LINKEDEYE_AUTOMATION_RETENTION_DAYS` | `90` | | Days of automation / StackStorm execution history kept. |

### Process and container variables

| Variable | Default | Read by | Description |
|---|---|---|---|
| `GUNICORN_BIND` | `0.0.0.0:8000` | gunicorn.conf.py, healthcheck | Listen address(es), comma-separated (e.g. `0.0.0.0:8000,[::]:8000`). The health check probes the first TCP one. |
| `GUNICORN_WORKERS` | `2 × CPU limit + 1` (max 8) | gunicorn.conf.py | Worker processes (CPU quota aware). |
| `GUNICORN_THREADS` | `4` | gunicorn.conf.py | Threads per worker (`1` switches to sync workers). |
| `GUNICORN_TIMEOUT` | `60` | gunicorn.conf.py | Seconds before a stuck worker is restarted. |
| `GUNICORN_GRACEFUL_TIMEOUT` | `30` | gunicorn.conf.py | Seconds to finish in-flight requests on shutdown. |
| `GUNICORN_KEEPALIVE` | `5` | gunicorn.conf.py | Keep-alive seconds towards the proxy. |
| `GUNICORN_MAX_REQUESTS` | `1000` | gunicorn.conf.py | Recycle workers after N requests (± 10 % jitter); `0` disables. |
| `GUNICORN_FORWARDED_ALLOW_IPS` | `127.0.0.1,::1` | gunicorn.conf.py | Peers whose `X-Forwarded-Proto` is trusted. |
| `GUNICORN_LOG_LEVEL` | `info` | gunicorn.conf.py | gunicorn error-log level. |
| `GUNICORN_ACCESS_LOG` | `-` (stdout) | gunicorn.conf.py | Access-log target, or `off`. |
| `GUNICORN_LOG_HEALTHZ` | `false` | gunicorn.conf.py | Also log successful `/healthz` requests. |
| `GUNICORN_WSGI_APP` | `container_wsgi:application` | gunicorn.conf.py | WSGI callable (Django + WhiteNoise wrapper). |
| `HEALTHCHECK_MAX_HEARTBEAT_AGE` | `300` | healthcheck.py | Max seconds since the scheduler heartbeat before probes is unhealthy. |
| `LINKEDEYE_IMAGE` | `linkedeye:9.0` | docker-compose.yml | Image to run / tag when building. |
| `LINKEDEYE_DB_EXTRAS` | `postgres` | docker-compose.yml | `DB_EXTRAS` build argument. |
| `WEB_PUBLISH` | `127.0.0.1:8000` | docker-compose.yml | Host address:port for the console. |
| `PROMETHEUS_PUBLISH`, `ALERTMANAGER_PUBLISH` | `127.0.0.1:9090`, `127.0.0.1:9093` | docker-compose.yml | Host ports of the observability profile. |
| `PROMETHEUS_RETENTION` | `15d` | docker-compose.yml | Prometheus TSDB retention. |

## Backups

The database is the only state: configuration records, check history, tickets, CMDB, audit log, users. The
image, static files and Prometheus data can be recreated; keep `.env` / the Kubernetes Secret in your secret
store, not in a backup of the host.

**PostgreSQL, compose** (custom-format dump, consistent while the console runs):

```bash
docker compose exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' > "linkedeye-$(date +%F-%H%M).dump"
```

**PostgreSQL, Kubernetes / external server:** scheduled in-cluster dumps come from
`deploy/kubernetes/optional/backup-cronjob.yaml` (not applied by default): a CronJob running `pg_dump -Fc`
nightly at 01:17 Asia/Kolkata into the PVC `linkedeye-backups`, keeping 14 days, using the ConfigMap / Secret
connection settings and the same restricted security context as the console (the NetworkPolicy already admits
it to the database). Set the storage class, then `kubectl apply -f deploy/kubernetes/optional/backup-cronjob.yaml`;
run one immediately with `kubectl -n fs-linkedeye create job --from=cronjob/linkedeye-db-backup backup-now`.
Ad hoc, from any machine that can reach the database:

```bash
PGPASSWORD='<password>' pg_dump -h <db host> -U linkedeye -d linkedeye -Fc -f "linkedeye-$(date +%F).dump"
```

With a managed database or an operator, prefer its point-in-time recovery (WAL archiving) and keep a nightly
`pg_dump` as a portable copy. **MySQL:** `mysqldump --single-transaction --routines linkedeye > linkedeye.sql`.
**SQLite (trials only):** `sqlite3 /app/data/linkedeye.sqlite3 ".backup '/backup/linkedeye.sqlite3'"`.

Run the dump on a schedule (host cron or a Kubernetes CronJob), copy it off the host, keep e.g. 7 daily /
4 weekly / 12 monthly copies, and **test a restore** into a scratch database regularly.

**Restore (compose):**

```bash
docker compose stop web probes
docker compose exec -T db sh -c 'pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --clean --if-exists --no-owner' < linkedeye-2026-11-01-0200.dump
docker compose run --rm migrate          # brings an older dump up to the running release
docker compose start web probes
```

On Kubernetes scale `linkedeye-web` and `linkedeye-probes` to 0, restore with `pg_restore` the same way,
re-run the migration Job, then scale back (web 2, probes **1**).

## Upgrades

Migrations only move forward. Take a backup before every upgrade; rolling back the code after a release that
changed the schema means restoring that backup.

**Compose:**

```bash
docker compose exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc' > pre-upgrade.dump
git pull                                   # or set LINKEDEYE_IMAGE to the new tag
docker compose build                       # or: docker compose pull
docker compose up -d                       # migrate runs first; web and probes are recreated after it exits 0
docker compose ps
```

**Kubernetes:**

```bash
# 1. backup (above)  2. set the new tag in kustomization.yaml (images[0].newTag)
kubectl -n fs-linkedeye delete job linkedeye-migrate --ignore-not-found     # Jobs are immutable
kubectl apply -k deploy/kubernetes
kubectl -n fs-linkedeye wait --for=condition=complete job/linkedeye-migrate --timeout=15m
kubectl -n fs-linkedeye rollout status deploy/linkedeye-web deploy/linkedeye-probes
```

New web pods wait for the migration Job in their init container while the old pods keep serving; the probes
Deployment is recreated (never two schedulers at once). Roll back code with `kubectl rollout undo` only when the
release had no migrations; otherwise restore the backup with the old image. With Argo CD or Helm, run the
migration as a PreSync / pre-upgrade hook.

**Rotating secrets:** `LINKEDEYE_SECRET_KEY` (signs everyone out), webhook / ingest tokens (update Alertmanager
and log shippers at the same time; in compose `docker compose --profile observability up -d --force-recreate web
alertmanager`, because the Alertmanager token file is only written when the container is created) and the database password (`ALTER USER linkedeye WITH PASSWORD '…'` first,
then update `.env` / the Secret and restart; for the compose `db` service the variable only initialises an
empty volume).

## Monitoring the console itself

* `GET /healthz` (no authentication; checks the database) from a probe **outside** the cluster / host gives an
  independent view of availability.
* Scheduler: **Administration → System health** shows the heartbeat; the `probes` container turns unhealthy
  when it stalls, and the console emits a warning event when check results stop arriving.
* Alert on container restarts of `linkedeye-probes` and on the migration Job failing.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `400 Bad Request` on every page or health check | The `Host` header is not in `LINKEDEYE_ALLOWED_HOSTS`. Add the public name; keep `web`/`localhost` (compose) or the `linkedeye-web…` names (Kubernetes). |
| `403 CSRF verification failed` on sign-in | Add the exact origin (`https://host[:port]`) to `LINKEDEYE_CSRF_TRUSTED_ORIGINS`; make sure the proxy sends `X-Forwarded-Proto` and `GUNICORN_FORWARDED_ALLOW_IPS` covers it. |
| Sign-in returns to the login page | Secure cookies over plain HTTP on a non-localhost name. Use HTTPS. |
| Pages unstyled | Static files missing: the image must be built with this Dockerfile (collectstatic at build). Check `curl -I https://host/static/linkedeye/app.css`. |
| Pods stuck in `Init:0/1` | The migration Job has not run or failed: `kubectl -n fs-linkedeye logs job/linkedeye-migrate`. |
| `probes` unhealthy, "heartbeat from another host" | A second scheduler is writing to this database. Find and stop it. |
| `probes` unhealthy, "run_probes is stalled" | A pass is hanging; check its logs and the targets' timeouts, then restart it. |
| Alertmanager gets 503 / 401 | `LINKEDEYE_ALERTMANAGER_WEBHOOK_TOKEN` unset in the console / token mismatch with Alertmanager's credentials file. In compose, recreate both after a change (`up -d --force-recreate web alertmanager`). |
| `alertmanager` container unhealthy (compose) | `LINKEDEYE_ALERTMANAGER_WEBHOOK_TOKEN` is empty in `.env`, so there is no token file to send. Set it and recreate the container. |
| Pod / gunicorn exits with `still hold '<REPLACE ...>' placeholders` | A Secret was created from `secret.template.yaml` without replacing every value. Set real values or delete the unused keys. |
| Container exits with `ValueError` at start-up | A numeric `LINKEDEYE_*` variable is set to an empty string; remove the line. |
| `RuntimeError: Set LINKEDEYE_SECRET_KEY` | No secret key and DEBUG off. |

## Validating the bundle

`python deploy/validate.py` (needs PyYAML) checks the compose file, Kubernetes manifests, Prometheus /
Alertmanager configuration and this document against each other: single probes replica and Recreate strategy,
`/healthz` probes, non-root read-only pods, matching labels and selectors, placeholder-only secrets, every
`LINKEDEYE_*` name being a real setting and every setting being documented here (and nothing documented that
the application does not read), and the preflight placeholder guard in the init containers and migration Job.
`python -m unittest discover -s deploy/tests -v` holds the regression tests for `gunicorn.conf.py`,
`deploy/docker/healthcheck.py` and `validate.py` itself (it runs the validator against deliberately broken
copies of the bundle). CI runs both together with
`docker compose config`, `promtool` / `amtool`, the test suite on SQLite and PostgreSQL, and an image build plus
smoke test (no push).
