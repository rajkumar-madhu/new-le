# syntax=docker/dockerfile:1
#
# LinkedEye console image: one image, two processes.
#   web     gunicorn (default CMD, see gunicorn.conf.py)
#   probes  python manage.py run_probes   (run EXACTLY ONE of these per database)
#
# Build:
#   docker build -t linkedeye:9.0 .                                  # PostgreSQL driver (default)
#   docker build --build-arg DB_EXTRAS="postgres mysql" -t linkedeye:9.0 .
#   docker build --build-arg DB_EXTRAS="" -t linkedeye:9.0 .          # SQLite only
# Behind a TLS-intercepting proxy, hand pip your CA bundle without baking it into the image:
#   docker build --secret id=pip_ca,src=/path/to/ca-bundle.pem -t linkedeye:9.0 .

ARG PYTHON_VERSION=3.12

# ---------------------------------------------------------------- build stage: virtualenv with dependencies
FROM python:${PYTHON_VERSION}-slim AS builder

ARG DB_EXTRAS="postgres"
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

# mysqlclient compiles against the MySQL client headers; nothing else needs a compiler.
RUN case " ${DB_EXTRAS} " in \
      *" mysql "*) apt-get update \
        && apt-get install -y --no-install-recommends build-essential pkg-config default-libmysqlclient-dev \
        && rm -rf /var/lib/apt/lists/* ;; \
    esac

RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH

WORKDIR /build
COPY requirements*.txt ./
RUN --mount=type=secret,id=pip_ca \
    set -eu; \
    if [ -s /run/secrets/pip_ca ]; then export PIP_CERT=/run/secrets/pip_ca; fi; \
    set -- -r requirements.txt; \
    for extra in ${DB_EXTRAS}; do \
      if [ ! -f "requirements-${extra}.txt" ]; then echo "unknown DB_EXTRAS entry: ${extra}" >&2; exit 1; fi; \
      set -- "$@" -r "requirements-${extra}.txt"; \
    done; \
    pip install "$@"; \
    pip check

# ---------------------------------------------------------------- runtime stage
FROM python:${PYTHON_VERSION}-slim AS runtime

ARG DB_EXTRAS="postgres"
ARG VERSION="9.0"
ARG REVISION=""

LABEL org.opencontainers.image.title="LinkedEye console" \
      org.opencontainers.image.description="LinkedEye ITSM & monitoring console (Django)" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:$PATH \
    DJANGO_SETTINGS_MODULE=linkedeye.settings

# Runtime library for mysqlclient only when that driver was built in.
RUN case " ${DB_EXTRAS} " in \
      *" mysql "*) apt-get update \
        && apt-get install -y --no-install-recommends libmariadb3 \
        && rm -rf /var/lib/apt/lists/* ;; \
    esac \
    && groupadd --system --gid 10001 linkedeye \
    && useradd --system --uid 10001 --gid linkedeye --home-dir /app --no-create-home \
       --shell /usr/sbin/nologin linkedeye

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
COPY . .

# Static files are collected at build time with a throwaway key (settings refuse to load without one when
# DEBUG is off). The key exists only for this RUN step and is not stored in the image. Byte-code is
# compiled now so the read-only root filesystem used in Kubernetes is never written to.
# /app/data is the only writable path in the image (for an SQLite database in single-host trials).
RUN LINKEDEYE_SECRET_KEY="build-only-dummy-key-not-used-at-runtime" LINKEDEYE_DEBUG=false \
      python manage.py collectstatic --noinput --verbosity 0 \
    && python -m compileall -q -j 0 /app /opt/venv > /dev/null \
    && mkdir -p /app/data \
    && chown linkedeye:linkedeye /app/data

USER 10001:10001
EXPOSE 8000

# Web containers: /healthz through gunicorn. The probes service overrides this with
# `python deploy/docker/healthcheck.py probes` (see docker-compose.yml / the Kubernetes manifests).
HEALTHCHECK --interval=30s --timeout=6s --start-period=40s --retries=3 \
    CMD ["python", "/app/deploy/docker/healthcheck.py", "web"]

CMD ["gunicorn", "--config", "/app/gunicorn.conf.py"]
