# Uptime Status

A small, self-hosted uptime status page. Add public domains in the admin panel; each one is
requested on its own interval, its response time is recorded, and the public page shows live
status, 90-day history, response times and incidents.

- **Backend:** Python 3.13, FastAPI, SQLAlchemy + Alembic (SQLite). Four runtime dependencies.
- **Frontend:** plain HTML/CSS/JS, no build step, no external assets, strict CSP.
- **Auth:** one admin. Username and scrypt password hash live in a file, no user management.
- **Deployment:** Docker, non-root, read-only filesystem, all capabilities dropped.

## Features

- Public status page: overall state, monthly overall-uptime calendar with month navigation,
  per-service 90-day uptime bars with tooltips, 24h / 7d / 30d uptime, response time with a
  24h sparkline, service search, current and past incidents, light and dark theme.
- Admin panel at `/admin`: add, edit, pause, delete monitors, trigger a check, view recent
  checks, delete false-alarm incidents, set the page title and description.
- Per-monitor check interval (10 s to 24 h) and timeout.
- Monitors can be hidden from the public page, and the URL is only shown publicly if you allow it.
- Raw checks are kept for 30 days (configurable). Daily rollups are kept indefinitely, so
  history stays cheap.

## Quick start

```bash
git clone https://github.com/Ivole32/uptime-status.git
cd uptime-status
docker compose build
```

**1. Create the admin credentials file.** Generate a password hash (min. 12 characters):

```bash
docker run --rm -it uptime-status:local python -m app.cli hash-password
```

Any Python 3.11+ works too, since the CLI only uses the standard library: `python -m app.cli hash-password`.

```bash
cp config/admin.toml.example config/admin.toml
```

Put your username and the printed `password_hash` line into `config/admin.toml`:

```toml
username = "ivo"
password_hash = "$scrypt$ln=15,r=8,p=1$...$..."
```

On Linux, let only the container user (UID 10001) read it:

```bash
sudo chown 10001:10001 config/admin.toml && sudo chmod 0400 config/admin.toml
```

**2. Configure** (optional): `cp .env.example .env` and set at least `UPTIME_ALLOWED_HOSTS`.

**3. Start:**

```bash
docker compose up -d
```

The app listens on `127.0.0.1:8000`. Open `http://localhost:8000/admin` to sign in.

### Changing the username or password

Edit `config/admin.toml`. The change applies on the next request, no restart needed, and
**every existing session is signed out**. If the file is missing or invalid, admin login is
disabled (the public page keeps working) and an error is logged.

## Production: put it behind HTTPS

The container only speaks plain HTTP on localhost. Terminate TLS in a reverse proxy. Example
`Caddyfile`:

```
status.example.com {
    reverse_proxy 127.0.0.1:8000
}
```

Then set in `.env`:

```env
UPTIME_ALLOWED_HOSTS=status.example.com
```

The service runs on its own dedicated bridge network, `uptime-status`, with host interface
`br-uptime`. Containers from other stacks cannot reach it. The network's subnet is pinned to
`172.30.0.0/24`. A proxy on the Docker host
reaches the container from that network's gateway `172.30.0.1`, which is trusted for
`X-Forwarded-For` by default. The login rate limiter needs this to tell clients apart. If
that subnet clashes with your network, change `UPTIME_SUBNET` and
`UPTIME_FORWARDED_ALLOW_IPS` together. If your proxy runs in another container, don't
put it on `uptime-status`. Instead, use a shared `proxy` network that only the proxy and
the services it fronts join (see the commented block in `docker-compose.yml`), and set
`UPTIME_FORWARDED_ALLOW_IPS` to the proxy container's address. The proxy must pass the original
`Host` header: Caddy does this by default, and nginx needs `proxy_set_header Host $host;`.

## Configuration

All settings are environment variables (see `.env.example`):

| Variable | Default | Purpose |
| --- | --- | --- |
| `UPTIME_ALLOWED_HOSTS` | *(any)* | Comma-separated hostnames to answer to (Host header check). |
| `UPTIME_COOKIE_SECURE` | `true` | Secure session cookie and HSTS. Keep on behind HTTPS. |
| `UPTIME_FORWARDED_ALLOW_IPS` | `172.30.0.1` | Proxy IPs/CIDRs whose `X-Forwarded-*` headers are trusted. |
| `UPTIME_SUBNET` | `172.30.0.0/24` | Docker network subnet (compose only). |
| `UPTIME_ALLOWED_PORTS` | `80,443,8080,8443` | Ports monitors may use. `*` allows any port. |
| `UPTIME_ALLOW_PRIVATE_TARGETS` | `false` | Allow monitoring private/internal addresses (turns off SSRF protection). |
| `UPTIME_SESSION_TTL_HOURS` | `12` | Admin session lifetime. |
| `UPTIME_RAW_RETENTION_DAYS` | `30` | How long individual checks are kept. |
| `UPTIME_PUBLIC_REFRESH_SECONDS` | `30` | Auto-refresh interval of the public page. |
| `UPTIME_PUBLIC_CACHE_SECONDS` | `10` | Server-side cache of the public status payload. |
| `UPTIME_CHECK_CONCURRENCY` | `10` | Maximum checks running at once. |
| `UPTIME_CHECK_RETRIES` | `1` | Immediate retries before a check counts as failed. |
| `UPTIME_MAX_MONITORS` | `200` | Upper limit on monitors. |
| `UPTIME_LOGIN_MAX_ATTEMPTS` | `5` | Failed logins per IP per window. |
| `UPTIME_LOGIN_WINDOW_MINUTES` | `15` | Rate-limit window. |
| `UPTIME_ENABLE_API_DOCS` | `false` | Expose OpenAPI docs at `/api/docs`. |

## How checks work

- You enter a domain (`example.com`) or a URL. Bare domains become `https://domain/`.
- The checker sends a `GET`, follows up to 5 redirects, and counts any final status below 400
  as **up**. 4xx/5xx, timeouts, DNS, TLS and connection errors count as **down**. A failed check
  is retried once after 2 seconds before it is recorded.
- **Response time** is the time from opening the connection until the response headers
  arrive, including the TLS handshake and redirects.
- When a monitor goes down an incident is opened, and it is resolved on the next successful check.
- If checks stop arriving for a monitor (more than two intervals), the public page shows
  "No recent data" instead of a stale status.
- The public page shows coarse error reasons only (for example `HTTP 503`, `DNS resolution failed`,
  or `Service unreachable`). The admin panel shows the exact reason.
- TLS certificates are always verified. An expired or invalid certificate counts as down.
- Only public addresses are reachable (see SSRF protection in [SECURITY.md](SECURITY.md)).

The scheduler runs inside the web process. Run exactly **one** instance/worker (the
default). SQLite is the supported database.

## Development

```bash
python -m venv .venv
.venv/bin/pip install -r requirements-dev.txt     # Windows: .venv\Scripts\pip
.venv/bin/python -m pytest
```

Run locally without Docker:

```bash
export UPTIME_DATABASE_URL=sqlite:///./dev.db UPTIME_CREDENTIALS_FILE=config/admin.toml
python -m app
```

Schema changes go through Alembic:

```bash
alembic revision --autogenerate -m "describe change"
alembic upgrade head
```

Migrations run automatically when the container starts.

## Project layout

```
app/
  main.py        FastAPI app, middleware, static pages
  __main__.py    entry point: run migrations, then uvicorn
  auth.py        credentials file, sessions, CSRF, login rate limiting
  passwords.py   scrypt hashing (stdlib only)
  checker.py     HTTP(S) probe with SSRF protection
  scheduler.py   background check loop, incidents, daily rollups, retention
  stats.py       public status payload
  routes/        public, auth and admin API
  static/        HTML, CSS, JS
migrations/      Alembic migrations
tests/           pytest suite
```
