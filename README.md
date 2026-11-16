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
  checks, post incident updates and post-mortems, delete false-alarm incidents, set the page
  title and description, and write the imprint and privacy policy.
- Incident updates: each incident has a public page at `/incidents/<id>`, linked from the status
  page. Post updates tagged *Investigating*, *Identified*, *Monitoring*, *Update* or *Resolved*,
  give the incident a title, and add a post-mortem. The tags are for your visitors only: whether
  an incident is ongoing still follows the checks. Resolved incidents are pruned after 400 days,
  except those you wrote a title, update or post-mortem for, which are kept.
- Imprint (`/imprint`) and privacy policy (`/privacy`), linked in the footer once they have
  text. They, incident updates and post-mortems support a small Markdown subset: `# Heading`, `- list`, `1. list`, `**bold**` and
  `[text](https://…)` links. HTML is shown as plain text.
- `robots.txt` and `sitemap.xml` (status page, legal pages and public incident pages), with
  absolute URLs from `UPTIME_PUBLIC_URL` or your first allowed host.
- Per-monitor check interval (10 s to 24 h) and timeout.
- Monitors can be hidden from the public page, and the URL is only shown publicly if you allow it.
- Push alerts through [Pushgate](https://github.com/Ivole32/pushgate) when a service stays
  down longer than a delay you choose, globally or per monitor, plus a notice when it recovers.
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
username = "admin"
password_hash = "$scrypt$ln=15,r=8,p=1$...$..."
```

On Linux, make it readable for the container user, and for nobody else:

```bash
sudo scripts/fix-config-permissions.sh
```

The app runs as UID 10001 inside the container, but which host user that is depends on Docker.
Without user-namespace remapping it is 10001. With `userns-remap` it is shifted, typically to
110001, so a plain `chown 10001` locks the container out. The script asks Docker for the actual
mapping, gives `config/` (mode `0500`) and `admin.toml` (mode `0400`) to that user, and checks
that the container can read the file. It builds the image first if needed.

**2. Configure** (optional): `cp .env.example .env` and set at least `UPTIME_ALLOWED_HOSTS`.

**3. Start:**

```bash
docker compose up -d
```

The app listens on `127.0.0.1:8000`. Open `http://localhost:8000/admin` to sign in.

### Changing the username or password

Edit `config/admin.toml` with any tool. The change applies on the next request, no restart
needed, and **every existing session is signed out**. The log then shows
`Loaded admin credentials from /config/admin.toml (fingerprint …)` with a new fingerprint, so
you can confirm the change took effect. Some editors replace the file and reset its owner, so
run `sudo scripts/fix-config-permissions.sh` again after editing. If the file is missing,
unreadable or invalid, admin login is disabled (the public page keeps working) and an error is
logged. For an unreadable file, the error names the host UID that must own it.

The compose file mounts the whole `config/` directory, not the single file. Docker pins a
single-file mount to the original file, so changes saved by editors or tools that write a new
file and rename it (`sed -i`, vim, Ansible) would never reach the container.

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

### Restrict the container's outbound traffic (recommended)

The app refuses private, loopback and link-local targets itself (see [SECURITY.md](SECURITY.md)).
Two gaps remain that only the host can close:

- The Docker host's **own public IP** is a valid public target. Connections from the container
  to it arrive with the container's private source address (`172.30.0.x`), which host services
  and reverse-proxy vhosts often treat as "internal".
- If the app-level check ever had a bug, nothing else would stop it.

First, list the host's public addresses in `UPTIME_BLOCKED_NETWORKS` (for example
`UPTIME_BLOCKED_NETWORKS=203.0.113.10,2001:db8::10`). This also covers cloud setups where the
public IP is NAT-ed and not on any host interface.

Then add host firewall rules for the `br-uptime` interface. Traffic from a container to an
address of the host itself goes through the `INPUT` chain, while traffic to other machines is
forwarded through `DOCKER-USER`. Both are needed:

```bash
# Container -> the host itself (any host address): only DNS, nothing else.
iptables -I INPUT 1 -i br-uptime -m conntrack --ctstate NEW -j DROP
iptables -I INPUT 1 -i br-uptime -p udp --dport 53 -j ACCEPT
iptables -I INPUT 1 -i br-uptime -p tcp --dport 53 -j ACCEPT

# Container -> other machines: no private or link-local networks, except DNS.
iptables -I DOCKER-USER 1 -i br-uptime -m conntrack --ctstate NEW \
  -d 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,100.64.0.0/10,169.254.0.0/16 -j REJECT
iptables -I DOCKER-USER 1 -i br-uptime -p udp --dport 53 -j RETURN
iptables -I DOCKER-USER 1 -i br-uptime -p tcp --dport 53 -j RETURN
```

Replies to connections the host opens (your reverse proxy talking to the app) are not `NEW`, so
they are unaffected. The DNS exceptions keep name resolution working when your resolver lives
on the host or in your LAN. Make the rules persistent with your distribution's firewall tooling,
and load them after Docker has started (Docker creates `DOCKER-USER`). If you enable IPv6 on the
network, add the same rules with `ip6tables` and `fc00::/7`, `fe80::/10`.

Verify from inside the container. The first command must fail, the second must succeed:

```bash
docker compose exec uptime python -c "import socket; socket.create_connection(('<host public IP>', 443), 3)"
docker compose exec uptime python -c "import socket; socket.create_connection(('example.com', 443), 3)"
```

## Push alerts (Pushgate)

Uptime Status can send a push notification to your phone through a
[Pushgate](https://github.com/Ivole32/pushgate) server when a service has been down for longer
than you allow, and another one when it is back up.

**1. Create a key in Pushgate.** In the Pushgate app, *Service API keys → Create key*, e.g.
named `uptime`. The name is put in front of every notification title (`uptime: Website is down`).
For high-priority alerts the key needs the `notifications:send:high` scope; otherwise choose
*Normal* priority in the alert settings.

**2. Store the key** in `config/pushgate.key` (one line, `pgk_…`) and fix its permissions.
`config/` belongs to the container user, so write it as root; pasting keeps the key out of your
shell history:

```bash
sudo sh -c 'cat > config/pushgate.key'   # paste the key, Enter, then Ctrl-D
sudo scripts/fix-config-permissions.sh
```

The file is read on every send, so a rotated key applies without a restart. For setups without
the config directory, `UPTIME_PUSHGATE_KEY` (the key itself) or `UPTIME_PUSHGATE_KEY_FILE` (another
path) work too.

**3. Point it at Pushgate** in `.env` and restart:

```env
UPTIME_PUSHGATE_URL=https://notify.example.com
```

Only `https` is accepted, and redirects are not followed, so the key is never sent anywhere else.

**4. Let the container reach Pushgate.** Pushgate only accepts senders from its `TRUSTED_CIDRS`:

- Pushgate on the **same host**: requests leave the container from the `uptime-status` network,
  so add `172.30.0.0/24` (or your `UPTIME_SUBNET`) to Pushgate's `TRUSTED_CIDRS`. If you use the
  firewall rules from [Restrict the container's outbound traffic](#restrict-the-containers-outbound-traffic-recommended),
  the `INPUT` rules block the host itself; allow HTTPS to it first:
  `iptables -I INPUT 1 -i br-uptime -p tcp --dport 443 -j ACCEPT`.
  Monitors still cannot reach the host, because its addresses are in `UPTIME_BLOCKED_NETWORKS`.
- Pushgate on **another machine**: add this server's public address to `TRUSTED_CIDRS`. If that
  machine has a private address, add an exception for it before the `DOCKER-USER` `REJECT` rule.

**5. Turn alerts on** in `/admin` → *Settings* → *Push alerts*: choose after how many minutes of
downtime to alert (default 5, `0` alerts on the first failed check), the priority, and whether
to be told about recovery and elevated latency. *Send test alert* checks the whole chain; the
card shows the last error if sending fails. Each monitor can override the delay or turn alerts
off in its edit dialog.

How it behaves:

- The delay counts from the first failed check, after the retry. An outage that ends earlier
  never sends anything. Each incident is alerted once.
- A recovery notice follows only for incidents that were alerted, and only within 24 hours.
  It replaces the outage notification on the phone (same Pushgate `tag`).
- More than three alerts at once (for example when the server itself lost its connection)
  are combined into one notification.
- Paused monitors are not alerted. If Pushgate is unreachable or refuses the request, the
  alert stays pending and is retried after a pause that grows from 30 s to 10 min (or
  Pushgate's `Retry-After`). Sending runs separately from the checks, so it never delays them.

## Configuration

All settings are environment variables (see `.env.example`):

| Variable | Default | Purpose |
| --- | --- | --- |
| `UPTIME_ALLOWED_HOSTS` | *(any)* | Comma-separated hostnames to answer to (Host header check). |
| `UPTIME_PUBLIC_URL` | *(derived)* | Public base URL, e.g. `https://status.example.com`, used in `sitemap.xml` and `robots.txt`. Defaults to the first `UPTIME_ALLOWED_HOSTS` entry (`https` while `UPTIME_COOKIE_SECURE` is on). Without either, `/sitemap.xml` returns 404. |
| `UPTIME_COOKIE_SECURE` | `true` | Secure session cookie and HSTS. Keep on behind HTTPS. |
| `UPTIME_FORWARDED_ALLOW_IPS` | `172.30.0.1` | Proxy IPs/CIDRs whose `X-Forwarded-*` headers are trusted. |
| `UPTIME_SUBNET` | `172.30.0.0/24` | Docker network subnet (compose only). |
| `UPTIME_ALLOWED_PORTS` | `80,443,8080,8443` | Ports monitors may use. `*` allows any port. |
| `UPTIME_ALLOW_PRIVATE_TARGETS` | `false` | Allow monitoring private/internal addresses (turns off SSRF protection). |
| `UPTIME_BLOCKED_NETWORKS` | *(none)* | Extra comma-separated IPs/CIDRs monitors may never reach, also when private targets are allowed. Put the Docker host's own public IPs here. |
| `UPTIME_SESSION_TTL_HOURS` | `12` | Admin session lifetime. |
| `UPTIME_RAW_RETENTION_DAYS` | `30` | How long individual checks are kept. |
| `UPTIME_PUBLIC_REFRESH_SECONDS` | `30` | Auto-refresh interval of the public page. |
| `UPTIME_PUBLIC_CACHE_SECONDS` | `10` | Server-side cache of the public status payload. |
| `UPTIME_CHECK_CONCURRENCY` | `10` | Maximum checks running at once; further due checks wait in a queue. Keep it at **25 or lower** with the compose `pids_limit: 128` (see below). |
| `UPTIME_CHECK_RETRIES` | `1` | Immediate retries before a check counts as failed. |
| `UPTIME_DEGRADED_FACTOR` | `2` | A check is slow above this multiple of the usual response time. `0` turns latency alerts off. |
| `UPTIME_DEGRADED_MIN_MS` | `200` | A check is only slow if it is also at least this many ms above the usual response time. |
| `UPTIME_MAX_MONITORS` | `200` | Upper limit on monitors. |
| `UPTIME_LOGIN_MAX_ATTEMPTS` | `5` | Failed logins per IP per window. |
| `UPTIME_LOGIN_WINDOW_MINUTES` | `15` | Rate-limit window. |
| `UPTIME_PUSHGATE_URL` | *(none)* | Pushgate base URL for push alerts, e.g. `https://notify.example.com`. See [Push alerts](#push-alerts-pushgate). |
| `UPTIME_PUSHGATE_KEY_FILE` | `/config/pushgate.key` | File holding the Pushgate API key. |
| `UPTIME_PUSHGATE_KEY` | *(none)* | The Pushgate API key itself, instead of the file. |
| `UPTIME_ENABLE_API_DOCS` | `false` | Expose OpenAPI docs at `/api/docs`. |

## How checks work

- You enter a domain (`example.com`) or a URL. Bare domains become `https://domain/`.
- The checker sends a `GET`, follows up to 5 redirects, and counts any final status below 400
  as **up**. 4xx/5xx, timeouts, DNS, TLS and connection errors count as **down**. A failed check
  is retried once after 2 seconds before it is recorded.
- **Response time** is the time from opening the connection until the response headers
  arrive, including the TLS handshake and redirects.
- When a monitor goes down an incident is opened, and it is resolved on the next successful check.
- **Elevated latency:** the usual response time is the 7-day average of successful checks, not
  counting checks made while degraded. When the last 3 checks are all slower than
  `UPTIME_DEGRADED_FACTOR` × usual *and* at least `UPTIME_DEGRADED_MIN_MS` above it, the monitor
  shows as **degraded** (yellow) and an "Elevated latency" incident is opened. It is resolved on the next normal check. Degraded
  checks still count as up. Nothing is flagged until a monitor has at least 20 successful checks.
- **Daily bars** (per service and in the monthly overview) are red if the day had any failed check,
  yellow if more checks were degraded than normal, and green otherwise. Hover a bar for the
  uptime, average response time and the number of failed and slow checks.
- If checks stop arriving for a monitor (more than two intervals), the public page shows
  "No recent data" instead of a stale status.
- The public page shows coarse error reasons only (for example `HTTP 503`, `DNS resolution failed`,
  or `Service unreachable`). The admin panel shows the exact reason.
- TLS certificates are always verified. An expired or invalid certificate counts as down.
- Only public addresses are reachable (see SSRF protection in [SECURITY.md](SECURITY.md)).

The scheduler runs inside the web process. Run exactly **one** instance/worker (the
default). SQLite is the supported database.

### Sizing `UPTIME_CHECK_CONCURRENCY`

At most `UPTIME_CHECK_CONCURRENCY` checks run at once; the rest wait their turn, so many
monitors never need more threads. Each running check uses up to three threads (the check, its
DNS lookup and a database write), on top of about 42 fixed threads for the web server. Threads
count against the container's `pids_limit`, so keep `pids_limit` at or above
`3 × UPTIME_CHECK_CONCURRENCY + 50`. With the shipped limit of 128, that means a concurrency of
**25 or lower**. Measured under those limits with the web thread pool saturated: 25 concurrent
checks peaked at 112 threads, while 40 hit the limit. The checks then failed to start and were
only retried a tick later.

Too low a value has the opposite cost: queued checks run late. A healthy check takes well under
a second, but during an outage each failing check can take `2 × timeout + 2 s` (with one retry).
To keep up even when everything is down, the concurrency should be at least
`monitors × (2 × timeout + 2) / interval`. For example, 50 monitors with a 10 s timeout and a 60 s
interval need about 19. If checks fall behind by more than two intervals, the public page shows
"No recent data" for the affected monitors.

## Development

```bash
python -m venv .venv
.venv/bin/pip install --require-hashes -r requirements-dev.txt   # Linux, as in CI
.venv/bin/python -m pytest
```

The `.txt` files are hashed lock files generated for Linux. On Windows or macOS, install
from `requirements-dev.in` instead (`.venv\Scripts\pip install -r requirements-dev.in`), which
pins the same top-level versions.

### Updating dependencies

Edit the `.in` files (`requirements.in` for runtime, `requirements-dev.in`,
`requirements-audit.in`), then regenerate all three locks on Linux with the image's Python:

```bash
docker run --rm -v "$PWD":/src -w /src python:3.13-slim-trixie sh -c '
  pip install -q pip-tools
  for f in requirements requirements-audit requirements-dev; do
    pip-compile -q --generate-hashes --allow-unsafe --strip-extras --no-emit-index-url -o $f.txt $f.in
  done'
```

The image installs `requirements.txt` with `--require-hashes --no-deps`, so every package,
including transitive ones, must be pinned with a matching hash. The build then runs `pip-audit`
against the installed packages and fails if any has a known vulnerability. Docker caches that
step, so use `docker compose build --no-cache` for a deployment to re-run it against current
advisories. To accept an advisory that has no fix yet, pass
`--build-arg PIP_AUDIT_ARGS="--ignore-vuln <ID>"`. CI runs the same audit, scans the image with
Trivy, and repeats both weekly.

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
  alerts.py      push alerts through Pushgate
  stats.py       public status payload
  routes/        public, auth and admin API
  static/        HTML, CSS, JS
migrations/      Alembic migrations
tests/           pytest suite
```

## License

Uptime Status is free software, licensed under the
[GNU General Public License v3.0](LICENSE). You may use, study, change and share it. If you
distribute it or a modified version, including as a container image, you must do so under the
same license and make the corresponding source code available. See [LICENSE](LICENSE) for the
full terms.

Contributions are welcome under the same license; see [CONTRIBUTING.md](CONTRIBUTING.md).
