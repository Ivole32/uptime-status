# Security

This document describes the security design of Uptime Status and the results of the security
audit done before the first release (2026-10-27).

## Reporting a vulnerability

Please do not open a public issue. Contact the maintainer privately.

## Design overview

| Area | Measure |
| --- | --- |
| Admin credentials | A single admin. Username and **scrypt** hash (N=2^15, r=8, p=1, 16-byte salt) live in `config/admin.toml`, mounted read-only. No passwords in the database or in environment variables. |
| Login | Constant-time comparison of username (via fixed-length digests) and password. A dummy hash is verified when no credentials are configured, so timing does not reveal that. Identical error for wrong username and wrong password. At most 2 concurrent scrypt verifications to bound memory. |
| Brute force | Sliding-window limit of 5 attempts per client per 15 min. IPv6 clients are grouped by /64. Each attempt is reserved atomically *before* the password is checked, so concurrent bursts cannot exceed the limit, and a successful login clears the client's bucket. There is no global cap, so nobody can lock the real admin out. Password checks never queue: if both hash slots are busy the request gets `429 Retry-After: 1` immediately, so login floods cannot tie up worker threads. Failed logins are logged with the client IP, never with the submitted username or password. |
| Client IP | The compose network is pinned, and only its gateway (where a reverse proxy on the host connects from) is trusted for `X-Forwarded-For`. |
| Sessions | 256-bit random token in an `HttpOnly`, `Secure`, `SameSite=Strict` cookie with the `__Host-` prefix. Only the SHA-256 of the token is stored. Sessions expire (12 h by default), are deleted on logout, and are bound to a fingerprint of the credentials file, so changing the username or password hash revokes all sessions at once. |
| CSRF | Per-session CSRF token required in the `X-CSRF-Token` header on every state-changing admin request. In addition, cross-origin `Origin` headers and `Sec-Fetch-Site: cross-site/same-site` are rejected, and request bodies must be `application/json`. HTML forms cannot send that without a CORS preflight, and no CORS is enabled. |
| XSS | The frontend never uses `innerHTML`. All data is inserted with `textContent` or attributes. Public links are only rendered for `http:`/`https:` URLs, with `rel="noopener noreferrer nofollow"`. Strict CSP: `default-src 'none'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'`, with no inline scripts or styles. |
| SSRF | See below. |
| Input validation | Pydantic models with `extra="forbid"`, length limits on every field, bounded integers, control characters stripped. Path IDs are bounded to 32-bit. Validation errors return field names and messages only, never the submitted value. |
| Headers | CSP, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, COOP/CORP, HSTS (when `COOKIE_SECURE`), `Cache-Control: no-store` on API responses, no `Server` header. |
| Information disclosure | OpenAPI docs disabled by default. Generic 500 responses, details only in server logs. Trailing-slash redirects are disabled, so the client-supplied `Host` header never reaches a `Location` header. The public API only exposes name, description, status, response times and coarse error categories (`HTTP 503`, `DNS resolution failed`, `TLS certificate invalid`, otherwise `Service unreachable`). Timeouts, refused connections and blocked targets all read the same, so the public page cannot be used as a port-scan oracle. The monitored URL is only exposed when "show link publicly" is set; intervals and hidden monitors are never exposed. |
| DoS | 64 KiB request body limit, 16 KiB header limit, 500 concurrent connections, 5 s keep-alive, public status cached for 10 s, monitor count capped (200), checks run on their own bounded thread pool with a hard per-check deadline, raw checks kept 30 days, incidents 400 days. |
| Container | Python slim image pinned by digest, multi-stage build, pip removed from the runtime image, runs as UID 10001, read-only root filesystem, `cap_drop: ALL` (effective capabilities verified as 0), `no-new-privileges`, PID and memory limits, port published on `127.0.0.1` only, code owned by root (not writable by the app user), credentials bind-mounted read-only and never copied into the image (`.dockerignore`). |
| Supply chain | Four pinned runtime dependencies. CI runs tests, `pip-audit` and a Docker build. Dependabot watches pip, Docker and GitHub Actions. |

### SSRF protection

The app fetches admin-supplied URLs, so it is an SSRF vector by nature. Defences:

1. **Input validation:** only `http`/`https`. No userinfo (`user:pass@`). Ports limited to
   `UPTIME_ALLOWED_PORTS` (default 80, 443, 8080, 8443). Hostnames are IDNA-normalised and
   then checked again for IP literals, which catches fullwidth digits. Shorthand IPv4 forms
   (`127.1`, `0x7f.1`, `2130706433`) are rejected. `localhost`, single-label names and
   `.local`, `.internal`, `.lan`, `.home.arpa`, `.localhost`, `.intranet` are rejected. IP
   literals must be public.
2. **Resolve, verify, pin:** on every check the stored URL is validated again, because the
   policy may have tightened since it was saved. The hostname is resolved, and *all* returned
   addresses must be public. "Public" means outside an explicit deny list (RFC 1918, loopback,
   link-local, CGNAT, documentation, benchmarking, multicast, reserved, ULA, site-local,
   Teredo, local NAT64 and more), plus `is_global`, so the result does not depend on the
   Python version. IPv4 addresses embedded in IPv6 (mapped, translated, compatible, NAT64 and
   6to4) are extracted and checked as IPv4. The connection then goes to exactly the verified
   IP, while TLS SNI and certificate validation still use the hostname. This closes the
   DNS-rebinding window between check and connect.
3. **Redirects** are followed manually (max. 5), and each hop goes through steps 1 and 2.
4. `http.client` does not honour proxy environment variables, so a proxy cannot be used to
   bypass the checks.
5. A watchdog closes the socket when the total time budget is spent, so a malicious server
   trickling bytes cannot hold worker threads. Probes run on their own thread pool, separate
   from database work.

Setting `UPTIME_ALLOW_PRIVATE_TARGETS=true` deliberately turns off the address checks, for
monitoring internal services. Only do that if you understand the consequences.

## Audit (2026-10-27)

Method:
- Manual code review of every backend, frontend and deployment file.
- A second, independent review by a reviewer who did not see the first one's conclusions.
- `pip-audit` of the pinned dependencies.
- Inspection of the running container.
- Automated tests for each security control (106 tests, run on Python 3.11 and 3.13).
- End-to-end attack attempts against the running container.

No critical or high-severity issues were found.

### Verified by test or live attack

- Login with a wrong password or wrong username returns an identical `401`.
- **Live:** the 6th attempt from one client returns `429`, while another client (different
  `X-Forwarded-For` behind the trusted gateway) can still try.
- A burst of logins while both hash slots are busy is rejected immediately and not counted
  against the client.
- Admin endpoints return `401` without a session. A missing or forged CSRF token returns `403`.
  A cross-origin `Origin` or `Sec-Fetch-Site: cross-site` returns `403`. A form-encoded body
  returns `415`. A body over 64 KiB returns `413`.
- The session token is not stored in plaintext. Expired sessions are rejected. Logout revokes
  the session. Editing `admin.toml` revokes all sessions. A missing `admin.toml` disables login.
- These targets are rejected at input validation:
  - `http://169.254.169.254/`, `127.0.0.1`, `localhost`, `file://`, `host.docker.internal`
  - `[::ffff:127.0.0.1]`, `::7f00:1`, `::ffff:0:7f00:1`, `fec0::1`, `192.0.0.192`
  - 6to4 and Teredo forms
  - fullwidth `１２７．０．０．１`, `127.1`, `0x7f.1`
  - non-allowlisted ports
- **Live:** `http://localtest.me:8000`, a public name that resolves to `127.0.0.1`, was blocked
  at check time.
- Simulated DNS rebinding, mixed public/private DNS records, and redirects to `127.0.0.1` or to
  a disallowed port are all blocked. Stored URLs that violate a tightened policy are blocked at
  check time. A slow-trickling server is cut off at the deadline.
- `<b>` in a monitor description renders as literal text on the public page.
- The container runs as `uid=10001`. Writing to `/app` fails (read-only). `CapEff=0`.
- `pip-audit`: no known vulnerabilities in fastapi 0.162.0, uvicorn 0.54.0, SQLAlchemy 2.1.6,
  alembic 1.20.1 and their dependencies.

### Findings fixed during the audit

| # | Severity | Finding | Fix |
| --- | --- | --- | --- |
| 1 | Medium | In the default deployment, connections reached the container from the Docker gateway, but `X-Forwarded-For` was only trusted from `127.0.0.1`. Every client shared one rate-limit bucket, so anyone could lock the admin out with 5 wrong passwords. | The compose network is pinned (`172.30.0.0/24`), and its gateway is trusted for `X-Forwarded-For` by default. Verified live. |
| 2 | Medium | A global cap of 100 failed logins per 15 min let anyone lock out the real admin, and per-IP buckets let an IPv6 attacker rotate through a /64. | The global cap was removed. IPv6 clients are bucketed per /64. |
| 3 | Medium | The rate-limit check and the failure record were not atomic, so a concurrent burst could exceed the limit. Queued scrypt calls also held worker threads, which stalled the public API. | Attempts are reserved atomically before hashing. The hash semaphore is non-blocking and returns an immediate `429`. |
| 4 | Medium | Check timeouts applied per socket read, so a trickling server could hold a check, and a shared executor, for a very long time, while the public page kept showing the last state. | A watchdog closes the socket at the total deadline. Probes have their own thread pool. Monitors without recent checks are shown as "No recent data". |
| 5 | Low | Leading and trailing whitespace was stripped from login passwords, so such passwords could never log in. | The password is no longer stripped. Only the username is. |
| 6 | Low | The SSRF filter missed IPv4-compatible and IPv4-translated IPv6, `fec0::/10`, and (on Python before 3.12.4) `192.0.0.192`, 6to4 and local NAT64. Any port was allowed. The public error text worked as a port-scan oracle. | An explicit deny list that works the same on every Python version. Embedded IPv4 is extracted and checked. A port allowlist. Stored URLs are validated again on every check. Public errors are coarse. |
| 7 | Low | `hmac.compare_digest` on usernames of different lengths can leak the length through timing. | Compare SHA-256 digests of both values. |
| 8 | Low | Huge integer path IDs (e.g. `10**30`) caused an integer overflow in the SQLite driver, which returned a 500. | IDs are bounded to `1..2^31-1`, so the request gets a `422`. |
| 9 | Low | A rate-limit key bug (found by live testing) made logins from IPv4 clients fail with a 500. | Fixed, with a regression test. |
| 10 | Info | Validation accepted fullwidth digits and shorthand IPv4 forms (these were still blocked at probe time). | IP literals are checked again after IDNA conversion, and numeric hostnames are rejected. |
| 11 | Info | Trailing-slash redirects built `Location` from the client's `Host` header. | `redirect_slashes=False`. A warning is logged when `UPTIME_ALLOWED_HOSTS` is unset. |
| 12 | Info | Incidents were never pruned, CI actions were pinned by tag, and the Dockerfile used `&& … \|\| true`, which could hide a failing build step. | Incidents are pruned after 400 days. Actions are pinned to commit SHAs. The Dockerfile steps are split so failures surface. |

### Accepted risks and operator responsibilities

- **Set `UPTIME_ALLOWED_HOSTS`** in production. Without it, any `Host` header is accepted
  (a warning is logged at startup).
- **Trusted proxy address.** Any process that can connect from the trusted gateway can set
  `X-Forwarded-For`. The port is published on `127.0.0.1` only, so that means local processes
  on the Docker host.
- **No TLS in the container.** HTTPS must be terminated by a reverse proxy. The `Secure`
  cookie will not work over plain HTTP except on `localhost`.
- **The admin can probe public hosts** on the allowed ports. This is inherent to an uptime
  monitor, and only the authenticated admin can do it.
- **uvicorn has no header-read timeout.** This is mitigated by publishing on loopback only,
  behind a reverse proxy, which should enforce its own timeouts.
- **Image CVEs.** The Debian base image was not scanned (Docker Scout needs a Docker Hub
  login). Run `docker scout cves uptime-status:local` or Trivy periodically. Dependabot
  keeps the digest current.
- **Single process.** The in-memory rate limiter and scheduler assume exactly one uvicorn
  worker, which is the default.
