# syntax=docker/dockerfile:1
# ---- Build stage: install dependencies into an isolated venv ----
# Base image pinned by digest for reproducible, tamper-evident builds (Dependabot keeps it current).
FROM python:3.13-slim-bookworm@sha256:93498f36dc7e24ef233bfdf6cc17d4b8bd32d94ee737143e906460d5f5a914c5 AS build
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /venv
COPY requirements.txt /tmp/requirements.txt
RUN /venv/bin/pip install --only-binary=:all: -r /tmp/requirements.txt
# pip is not needed at runtime; removing it shrinks the attack surface.
RUN /venv/bin/python -m pip uninstall -y pip

# ---- Runtime stage ----
FROM python:3.13-slim-bookworm@sha256:93498f36dc7e24ef233bfdf6cc17d4b8bd32d94ee737143e906460d5f5a914c5
LABEL org.opencontainers.image.title="uptime-status" \
      org.opencontainers.image.description="Self-hosted uptime status page"

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
COPY alembic.ini ./
COPY migrations ./migrations
COPY app ./app
RUN python -m compileall -q /app /venv

USER 10001:10001
EXPOSE 8000
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status == 200 else 1)"]

CMD ["python", "-m", "app"]
