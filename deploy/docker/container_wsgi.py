"""WSGI entry point used by gunicorn.conf.py (container image and bare-metal gunicorn).

It is linkedeye.wsgi.application with static files served by WhiteNoise:

* When settings.MIDDLEWARE already contains "whitenoise.middleware.WhiteNoiseMiddleware" (the recommended
  setup, see docs/DEPLOYMENT.md), the Django application is returned unchanged and the middleware serves
  /static/ with hashed, compressed, far-future-cached files.
* Otherwise the application is wrapped with WhiteNoise's WSGI layer so the console is still styled when
  DEBUG is off (Django itself never serves static files in production). Files are served from STATIC_ROOT,
  which `collectstatic` fills at image build time.
"""
import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "linkedeye.settings")

from django.conf import settings  # noqa: E402
from linkedeye.wsgi import application as django_application  # noqa: E402

WHITENOISE_MIDDLEWARE = "whitenoise.middleware.WhiteNoiseMiddleware"


def build(app=django_application):
    if WHITENOISE_MIDDLEWARE in settings.MIDDLEWARE:
        return app
    try:
        from whitenoise import WhiteNoise
    except ImportError:  # requirements.txt installs it; without it pages render unstyled but still work
        return app
    static_url = settings.STATIC_URL or "/static/"
    if not static_url.startswith("/"):
        static_url = "/" + static_url
    # Unhashed file names: keep the browser cache short so a new release's CSS/JS is picked up quickly.
    return WhiteNoise(app, root=str(settings.STATIC_ROOT), prefix=static_url, max_age=300)


application = build()
