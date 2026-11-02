"""LinkedEye console settings. All secrets and environment specifics come from
environment variables (see .env.example); nothing sensitive is committed."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def env(name, default=None):
    """LINKEDEYE_<name>; an empty value counts as unset, so `LINKEDEYE_PROBE_TIMEOUT=` in an env file keeps the default."""
    value = os.environ.get(f"LINKEDEYE_{name}")
    return default if value in (None, "") else value


def env_list(name, default=""):
    return [x.strip() for x in env(name, default).split(",") if x.strip()]


DEBUG = env("DEBUG", "false").lower() in ("1", "true", "yes")
SECRET_KEY = env("SECRET_KEY") or ("dev-only-insecure-key" if DEBUG else None)
if not SECRET_KEY:
    raise RuntimeError("Set LINKEDEYE_SECRET_KEY (or LINKEDEYE_DEBUG=true for local development).")

ALLOWED_HOSTS = env_list("ALLOWED_HOSTS", "localhost,127.0.0.1" if DEBUG else "")
CSRF_TRUSTED_ORIGINS = env_list("CSRF_TRUSTED_ORIGINS")
# Reverse proxies (IPs or CIDRs) whose X-Forwarded-For is believed for audit source IPs; empty = use the peer.
TRUSTED_PROXIES = env_list("TRUSTED_PROXIES")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "core",
    "probes",
    "urlchecker",
    "domainmonitor",
    "servicedesk",
    "cmdb",
    "network",
    "telemetry",
    "observe",
    "tcpcheck",
    "bodeod",
    "automation",
    "administration",
    "reports",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",  # serves collected static files (hashed, compressed)
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "core.middleware.LoginRequiredMiddleware",
]

ROOT_URLCONF = "linkedeye.urls"
WSGI_APPLICATION = "linkedeye.wsgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "core.context_processors.shell",
            ],
        },
    },
]

DATABASES = {
    "default": {
        "ENGINE": env("DB_ENGINE", "django.db.backends.sqlite3"),
        "NAME": env("DB_NAME", str(BASE_DIR / "db.sqlite3")),
        "USER": env("DB_USER", ""),
        "PASSWORD": env("DB_PASSWORD", ""),
        "HOST": env("DB_HOST", ""),
        "PORT": env("DB_PORT", ""),
        "CONN_MAX_AGE": int(env("DB_CONN_MAX_AGE", "60")),
        "CONN_HEALTH_CHECKS": True,
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 12}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = env("TIME_ZONE", "Asia/Kolkata")
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    # DEBUG (tests, runserver) needs no collectstatic; production serves hashed, compressed files
    "staticfiles": {"BACKEND": "django.contrib.staticfiles.storage.StaticFilesStorage" if DEBUG
                    else "whitenoise.storage.CompressedManifestStaticFilesStorage"},
}
WHITENOISE_MANIFEST_STRICT = False  # a template naming a missing static file gets a 404 asset, not a 500 page
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "dashboard"
LOGOUT_REDIRECT_URL = "login"

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"

# ---- LinkedEye ----
LINKEDEYE_TENANT = env("TENANT", "default")
LINKEDEYE_VERSION = "9.0"
PROBE_ALLOWED_PRIVATE_CIDRS = env_list("PROBE_ALLOWED_PRIVATE_CIDRS")
PROBE_TIMEOUT = float(env("PROBE_TIMEOUT", "10"))
PROBE_WORKERS = int(env("PROBE_WORKERS", "8"))
PROBE_RETENTION_DAYS = int(env("PROBE_RETENTION_DAYS", "30"))

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "loggers": {
        "linkedeye": {"handlers": ["console"], "level": env("LOG_LEVEL", "INFO")},
        # with DEBUG off, 500 tracebacks and DisallowedHost would otherwise only be mailed to (empty) ADMINS
        "django.request": {"handlers": ["console"], "level": "ERROR", "propagate": False},
        "django.security": {"handlers": ["console"], "level": "WARNING", "propagate": False},
    },
}

# ---- Notifications (critical/warning events) ----
NOTIFY_WEBHOOK_URLS = env_list("NOTIFY_WEBHOOK_URLS")        # JSON POST per event (Slack/Teams/Apprise/StackStorm…)
NOTIFY_EMAILS = env_list("NOTIFY_EMAILS")
NOTIFY_SEVERITIES = env_list("NOTIFY_SEVERITIES", "critical,warning")
EMAIL_BACKEND = env("EMAIL_BACKEND", "django.core.mail.backends.smtp.EmailBackend" if not DEBUG else "django.core.mail.backends.console.EmailBackend")
EMAIL_HOST = env("EMAIL_HOST", "localhost")
EMAIL_PORT = int(env("EMAIL_PORT", "25"))
EMAIL_HOST_USER = env("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = env("EMAIL_HOST_PASSWORD", "")
EMAIL_USE_TLS = env("EMAIL_USE_TLS", "false").lower() in ("1", "true", "yes")
DEFAULT_FROM_EMAIL = env("DEFAULT_FROM_EMAIL", "linkedeye@localhost")

# ---- Integrations (all optional; pages show "not connected" when unset) ----
PROMETHEUS_URL = env("PROMETHEUS_URL", "")                    # e.g. http://prometheus.fs-linkedeye:9090
PROMETHEUS_TIMEOUT = float(env("PROMETHEUS_TIMEOUT", "8"))
ALERTMANAGER_WEBHOOK_TOKEN = env("ALERTMANAGER_WEBHOOK_TOKEN", "")   # required bearer token for /api/v1/alertmanager/
LOG_INGEST_TOKEN = env("LOG_INGEST_TOKEN", "")               # required bearer token for /api/v1/logs/
STACKSTORM_URL = env("STACKSTORM_URL", "")                    # e.g. https://st2.fs-linkedeye/api/v1/webhooks/
STACKSTORM_API_KEY = env("STACKSTORM_API_KEY", "")
INCIDENT_AUTO_CREATE = env("INCIDENT_AUTO_CREATE", "true").lower() in ("1", "true", "yes")
NAGIOS_URL = env("NAGIOS_URL", "")                            # Nagios Core base URL (statusjson.cgi is appended)
NAGIOS_USER = env("NAGIOS_USER", "")
NAGIOS_PASSWORD = env("NAGIOS_PASSWORD", "")
NAGIOS_TIMEOUT = float(env("NAGIOS_TIMEOUT", "10"))
# Retention (days) for high-volume module data
LOG_RETENTION_DAYS = int(env("LOG_RETENTION_DAYS", "14"))
TELEMETRY_ALERT_RETENTION_DAYS = int(env("TELEMETRY_ALERT_RETENTION_DAYS", "90"))
AUTOMATION_RETENTION_DAYS = int(env("AUTOMATION_RETENTION_DAYS", "90"))
