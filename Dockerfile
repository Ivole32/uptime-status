# syntax=docker/dockerfile:1
# ---- Build stage: install dependencies into an isolated venv ----
# Base image pinned by digest for reproducible, tamper-evident builds (Dependabot keeps the
# digest current). Debian 13 "trixie" is the current stable release with full security support.
FROM python:3.13-slim-trixie@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb AS build
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /venv
COPY requirements.txt requirements-audit.txt /tmp/
# Every package, including transitive ones, is pinned and must match a known hash.
RUN /venv/bin/pip install --only-binary=:all: --require-hashes --no-deps -r /tmp/requirements.txt
RUN /venv/bin/pip check
# pip is not needed at runtime; removing it shrinks the attack surface.
RUN /venv/bin/python -m pip uninstall -y pip

# Deployment gate: the build fails if any package that ships has a known vulnerability.
# pip-audit runs from its own venv, which never reaches the runtime image. A cached layer
# skips the audit; `docker compose build --no-cache` re-runs it against today's advisories.
# To accept a specific advisory: --build-arg PIP_AUDIT_ARGS="--ignore-vuln GHSA-xxxx".
ARG PIP_AUDIT_ARGS=""
RUN python -m venv /audit \
 && /audit/bin/pip install --only-binary=:all: --require-hashes --no-deps -r /tmp/requirements-audit.txt \
 && /audit/bin/pip-audit --strict --path /venv/lib/python3.13/site-packages $PIP_AUDIT_ARGS

# ---- Runtime stage ----
FROM python:3.13-slim-trixie@sha256:2d44738ebf4ce5f63b9d9ea871e9c7cfdc0426f7b0c97cac915fd88ded1d86bb
LABEL org.opencontainers.image.title="uptime-status" \
      org.opencontainers.image.description="Self-hosted uptime status page" \
      org.opencontainers.image.licenses="GPL-3.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/venv/bin:$PATH \
    UPTIME_DATABASE_URL=sqlite:////data/uptime.db \
    UPTIME_CREDENTIALS_FILE=/config/admin.toml

RUN groupadd --system --gid 10001 uptime \
 && useradd --system --uid 10001 --gid uptime --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin uptime \
 && mkdir -p /data /config \
 && chown uptime:uptime /data \
 && chmod 0750 /data
RUN python -m pip uninstall -y pip

COPY --from=build /venv /venv
WORKDIR /app
# Application code is owned by root and not writable by the runtime user.
COPY LICENSE alembic.ini ./
COPY migrations ./migrations
COPY app ./app
# COPY keeps the permissions of the checkout. A checkout made with a strict umask
# (e.g. 077) would leave the code unreadable for the runtime user, so normalise it:
# readable by everyone, writable only by root.
RUN chmod -R u=rwX,go=rX /app \
 && python -m compileall -q /app /venv

USER 10001:10001
EXPOSE 8000
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status == 200 else 1)"]

CMD ["python", "-m", "app"]
