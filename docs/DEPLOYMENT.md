# Deployment notes

Two processes share one database:

| Process | Command | Replicas |
|---|---|---|
| Web | `gunicorn linkedeye.wsgi:application --bind 0.0.0.0:8000 --workers 4` | 2+ |
| Probe scheduler | `python manage.py run_probes` | **exactly 1** (two schedulers would double-check every target) |

* Run `python manage.py collectstatic` at build time and serve `staticfiles/` from the ingress or WhiteNoise.
* Health endpoint: `GET /healthz` (no auth; checks the database connection).
* Put the probe scheduler where it can reach the targets you monitor. Set
  `LINKEDEYE_PROBE_ALLOWED_PRIVATE_CIDRS` for internal ranges; keep everything else blocked.
* For an independent view of the console's own availability, monitor `/healthz` from a probe outside the
  cluster (as the architecture document recommends).
