"""Gunicorn configuration for the LinkedEye web process.

Used by the container image (CMD ["gunicorn", "--config", "/app/gunicorn.conf.py"]) and usable as-is outside
containers:  gunicorn --config gunicorn.conf.py

Every value can be overridden with an environment variable (all optional):

    GUNICORN_BIND                   listen address(es), comma-separated    0.0.0.0:8000
    GUNICORN_WORKERS                worker processes                       2 x CPUs + 1, capped at 8 (CPU limit aware)
    GUNICORN_THREADS                threads per worker (gthread)           4
    GUNICORN_TIMEOUT                seconds before a silent worker is killed   60
    GUNICORN_GRACEFUL_TIMEOUT       seconds to finish requests on shutdown  30
    GUNICORN_KEEPALIVE              keep-alive seconds behind a proxy       5
    GUNICORN_MAX_REQUESTS           recycle a worker after N requests       1000 (0 = never)
    GUNICORN_FORWARDED_ALLOW_IPS    proxies trusted for X-Forwarded-Proto   127.0.0.1,::1
    GUNICORN_LOG_LEVEL              error-log level                         info
    GUNICORN_ACCESS_LOG             "-" (stdout), a file path, or "off"     -
    GUNICORN_LOG_HEALTHZ            also log successful GET /healthz        false

Notes
* "Run check now" and saving a check probe the target synchronously inside the request (bounded by
  LINKEDEYE_PROBE_TIMEOUT), so threaded workers keep the console responsive while a probe waits.
* GUNICORN_FORWARDED_ALLOW_IPS decides whose X-Forwarded-Proto is believed (request.is_secure()). Set it to the
  ingress / reverse-proxy addresses, or "*" only when nothing but the proxy can reach the container
  (the Kubernetes manifests do this together with a NetworkPolicy).
"""
import os

from gunicorn.glogging import Logger

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _env(name, default):
    value = os.environ.get(name, "")
    return value.strip() if value.strip() else default


def _int(name, default, minimum=None):
    try:
        value = int(_env(name, str(default)))
    except ValueError:
        value = default
    return value if minimum is None else max(minimum, value)


def _binds(value):
    """GUNICORN_BIND may list several addresses separated by commas ("0.0.0.0:8000,[::]:8000")."""
    return [b.strip() for b in value.split(",") if b.strip()] or ["0.0.0.0:8000"]


def _cpu_limit():
    """CPUs this container may use: the cgroup quota when one is set, else the affinity mask."""
    try:
        cpus = len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        cpus = os.cpu_count() or 1
    try:  # cgroup v2
        with open("/sys/fs/cgroup/cpu.max") as fh:
            quota, period = fh.read().split()[:2]
        if quota != "max":
            cpus = min(cpus, max(1, int(int(quota) / int(period) + 0.999)))
    except (OSError, ValueError):
        try:  # cgroup v1
            with open("/sys/fs/cgroup/cpu/cpu.cfs_quota_us") as fq, open("/sys/fs/cgroup/cpu/cpu.cfs_period_us") as fp:
                quota, period = int(fq.read()), int(fp.read())
            if quota > 0:
                cpus = min(cpus, max(1, int(quota / period + 0.999)))
        except (OSError, ValueError):
            pass
    return max(1, cpus)


# The image's WSGI entry point: Django plus WhiteNoise for /static/ (see deploy/docker/container_wsgi.py).
pythonpath = os.path.join(BASE_DIR, "deploy", "docker")
wsgi_app = _env("GUNICORN_WSGI_APP", "container_wsgi:application")
chdir = BASE_DIR

bind = _binds(_env("GUNICORN_BIND", "0.0.0.0:8000"))
workers = _int("GUNICORN_WORKERS", min(2 * _cpu_limit() + 1, 8), minimum=1)
threads = _int("GUNICORN_THREADS", 4, minimum=1)
worker_class = "gthread" if threads > 1 else "sync"
timeout = _int("GUNICORN_TIMEOUT", 60, minimum=1)
graceful_timeout = _int("GUNICORN_GRACEFUL_TIMEOUT", 30, minimum=0)
keepalive = _int("GUNICORN_KEEPALIVE", 5, minimum=0)
max_requests = _int("GUNICORN_MAX_REQUESTS", 1000, minimum=0)
max_requests_jitter = max(0, max_requests // 10)

# Worker heartbeat files: /dev/shm is a tmpfs, so this works with a read-only root filesystem and avoids
# disk-backed /tmp stalls.
worker_tmp_dir = "/dev/shm" if os.path.isdir("/dev/shm") and os.access("/dev/shm", os.W_OK) else None

forwarded_allow_ips = _env("GUNICORN_FORWARDED_ALLOW_IPS", "127.0.0.1,::1")
proxy_allow_ips = forwarded_allow_ips

# Request limits (defence in depth; the ingress / reverse proxy should enforce its own).
limit_request_line = 8190
limit_request_fields = 100
limit_request_field_size = 8190

loglevel = _env("GUNICORN_LOG_LEVEL", "info")
errorlog = "-"
_access = _env("GUNICORN_ACCESS_LOG", "-")
accesslog = None if _access.lower() in ("off", "none", "false", "0") else _access
# client (first X-Forwarded-For hop when behind a proxy), request, status, bytes, referer, agent, duration in ms
access_log_format = '%({x-forwarded-for}i)s %(h)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(M)sms'

_LOG_HEALTHZ = _env("GUNICORN_LOG_HEALTHZ", "false").lower() in ("1", "true", "yes")


class LinkedEyeLogger(Logger):
    """Gunicorn's logger, minus successful health-check requests (kubelet / Docker poll /healthz every few
    seconds, which would otherwise drown the access log). Failed health checks are still logged."""

    def access(self, resp, req, environ, request_time):
        if not _LOG_HEALTHZ and environ.get("PATH_INFO") == "/healthz" and str(getattr(resp, "status", "")).startswith("200"):
            return
        super().access(resp, req, environ, request_time)


logger_class = LinkedEyeLogger

# Load the application in each worker (not the master): a database or settings error then shows up in the
# worker log with a traceback, and workers recycle cleanly with max_requests.
preload_app = False


def on_starting(server):
    # Refuse to serve with values copied unedited from deploy/kubernetes/secret.template.yaml: a published
    # placeholder used as LINKEDEYE_SECRET_KEY or as a webhook token would be a publicly known secret.
    import sys
    sys.path.insert(0, os.path.join(BASE_DIR, "deploy", "docker"))
    from healthcheck import placeholder_variables
    unedited = placeholder_variables(os.environ)
    if unedited:
        raise RuntimeError("refusing to start: these variables still hold '<REPLACE ...>' template placeholders: "
                           + ", ".join(unedited))
    server.log.info("LinkedEye web: %s worker(s) x %s thread(s), timeout %ss, bind %s",
                    workers, threads, timeout, ", ".join(bind))
