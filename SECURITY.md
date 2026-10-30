# Security Policy

The security of Uptime Status is taken seriously. If you discover a vulnerability, please follow
the guidelines below so it can be handled responsibly. The second half of this document
describes the security design of the application and what operators are responsible for.

## Supported versions

Only the latest version on the `main` branch receives security fixes.

| Version | Supported |
| --- | --- |
| Latest `main` branch | Yes |
| Older commits and builds | No |

If you run an older build, update to the latest `main` and rebuild the image
(`docker compose build --no-cache`) before reporting an issue.

## Reporting a vulnerability

Please **do not** report security vulnerabilities through public issues, discussions or pull
requests. Instead, contact the maintainer ([Ivole32](https://github.com/Ivole32)) privately.

Please include:

- A clear description of the vulnerability and its impact.
- Steps to reproduce it, if possible.
- The affected version (commit hash) and relevant configuration, such as `UPTIME_*` settings
  and how the app is deployed (Docker Compose, reverse proxy).
- Logs, screenshots or proof-of-concept code, if relevant. Remove passwords, password hashes,
  session cookies and other secrets first.

You will receive an acknowledgment as soon as possible.

## Response timeline

This is a small, actively maintained project, so response times may vary.

- **Initial response:** within a reasonable timeframe.
- **Fix or mitigation:** depending on severity and complexity.

## Disclosure policy

Vulnerabilities are disclosed publicly only after a fix or mitigation is available, or earlier
if disclosure is necessary to keep users safe. Please give the maintainer a reasonable amount of
time to release a fix before you publish details yourself.

## Scope

This policy covers:

- The application code (`app/`), including the public status page, the admin panel and API,
  the checker and the scheduler.
- Database migrations (`migrations/`).
- The container image and deployment files (`Dockerfile`, `docker-compose.yml`, `.env.example`,
  `config/admin.toml.example`).
- The CI workflow and dependency configuration (`.github/`, `requirements*.in`,
  `requirements*.txt`).

Not in scope:

- Third-party dependencies and the base image. These follow their own security policies. A
  problem in how this project uses them is in scope.
- Your reverse proxy, host and network configuration.
- Issues that need a setting the documentation warns against, such as
  `UPTIME_ALLOW_PRIVATE_TARGETS=true` or a missing `UPTIME_ALLOWED_HOSTS`, and the accepted
  risks listed below.

## Final note

Thank you for helping keep this project and its users secure. Responsible disclosure is
highly appreciated.

# Security design

## Overview

| Area | Measure |
| --- | --- |
| Admin credentials | A single admin. Username and **scrypt** hash (N=2^15, r=8, p=1, 16-byte salt) live in `config/admin.toml`, mounted read-only. No passwords in the database or in environment variables. |
| Login | Constant-time comparison of username (via fixed-length digests) and password. A dummy hash is verified when no credentials are configured, so timing does not reveal that. Identical error for wrong username and wrong password. At most 2 concurrent scrypt verifications to bound memory. |
| Brute force | Sliding-window limit of 5 attempts per client per 15 min. IPv6 clients are grouped by /64. Each attempt is reserved atomically *before* the password is checked, so concurrent bursts cannot exceed the limit, and a successful login clears the client's bucket. There is no global cap, so nobody can lock the real admin out. Password checks never queue: if both hash slots are busy the request gets `429 Retry-After: 1` immediately, so login floods cannot tie up worker threads. Failed logins are logged with the client IP, never with the submitted username or password. |
| Client IP | The compose network is pinned, and only its gateway (where a reverse proxy on the host connects from) is trusted for `X-Forwarded-For`. |
| Sessions | 256-bit random token in an `HttpOnly`, `Secure`, `SameSite=Strict` cookie with the `__Host-` prefix. Only the SHA-256 of the token is stored. Sessions expire (12 h by default), are deleted on logout, and are bound to a fingerprint of the credentials file, so changing the username or password hash revokes all sessions at once. |
| CSRF | Per-session CSRF token required in the `X-CSRF-Token` header on every state-changing admin request. In addition, cross-origin `Origin` headers and `Sec-Fetch-Site: cross-site/same-site` are rejected, and request bodies must be `application/json`. HTML forms cannot send that without a CORS preflight, and no CORS is enabled. |
| XSS | The frontend never uses `innerHTML`. All data is inserted with `textContent` or attributes. Public links are only rendered for `http:`/`https:` URLs, with `rel="noopener noreferrer nofollow"`. The imprint and privacy policy are stored as plain text and rendered client-side from a small Markdown subset straight into DOM nodes, so HTML in them is shown literally; their links are limited to `http:`, `https:`, `mailto:` and `tel:`, anything else stays plain text. The renderer's patterns run in linear time, so a long or malformed text cannot hang a visitor's browser. Strict CSP: `default-src 'none'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'`, with no inline scripts or styles. |
| SSRF | See below. |
| Input validation | Pydantic models with `extra="forbid"`, length limits on every field, bounded integers, control characters stripped. Path IDs are bounded to 32-bit. Validation errors return field names and messages only, never the submitted value. |
| Headers | CSP, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, COOP/CORP, HSTS (when `COOKIE_SECURE`), `Cache-Control: no-store` on API responses, no `Server` header. |
| Information disclosure | OpenAPI docs disabled by default. Generic 500 responses, details only in server logs. Trailing-slash redirects are disabled, so the client-supplied `Host` header never reaches a `Location` header. The public API only exposes name, description, status, response times and coarse error categories (`HTTP 503`, `DNS resolution failed`, `TLS certificate invalid`, otherwise `Service unreachable`). Timeouts, refused connections and blocked targets all read the same, so the public page cannot be used as a port-scan oracle. The monitored URL is only exposed when "show link publicly" is set; intervals and hidden monitors are never exposed. |
| DoS | 64 KiB request body limit (about 1.2 MB for saving the imprint or privacy policy, which are capped at 100,000 characters; the larger limit applies to those two exact paths only, and their body is read only after the session and CSRF token are checked, so anonymous clients cannot make the server buffer it), 16 KiB header limit, 500 concurrent connections, 5 s keep-alive, public status cached for 10 s, monitor count capped (200), checks run on their own bounded thread pool with a hard per-check deadline, raw checks kept 30 days, incidents 400 days. |
| Container | Python slim image on Debian 13 "trixie" (full Debian security support) pinned by digest, multi-stage build, pip removed from the runtime image, runs as UID 10001, read-only root filesystem, `cap_drop: ALL` (effective capabilities verified as 0), `no-new-privileges`, PID and memory limits, port published on `127.0.0.1` only, code owned by root (not writable by the app user), credentials bind-mounted read-only and never copied into the image (`.dockerignore`). |
| Supply chain | Four direct runtime dependencies. All 18 runtime packages, including transitive ones, are pinned in a hashed lock (`requirements.txt`, generated by pip-compile) and installed with `--require-hashes --no-deps`. The image build runs `pip-audit` on the installed packages and fails on any known vulnerability. CI runs tests, `pip-audit` on the lock, the Docker build and a Trivy image scan (HIGH/CRITICAL with a fix available fail the build), on every push and weekly. Dependabot watches pip, Docker and GitHub Actions. |

## SSRF protection

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
5. Every check has one absolute deadline covering DNS, connect, the TLS handshake and the
   response. DNS lookups run on a separate pool and the check stops waiting at the deadline.
   A shared watchdog thread shuts the socket down at the deadline in any phase, including a
   stalled connect or handshake, so a malicious server cannot hold worker threads. Probes run
   on their own thread pool, separate from database work.
6. **Operator deny list:** `UPTIME_BLOCKED_NETWORKS` adds IPs/CIDRs that are refused even when
   private targets are allowed, checked at input, after DNS and for embedded IPv4. Use it for
   the Docker host's own public IPs. Azure WireServer (`168.63.129.16`) is always blocked.
7. **Network layer (operator):** the README gives `INPUT` and `DOCKER-USER` rules for
   `br-uptime`, so even a bug in the checks above cannot reach the host or private networks.

Setting `UPTIME_ALLOW_PRIVATE_TARGETS=true` deliberately turns off the address checks, for
monitoring internal services. Only do that if you understand the consequences.

## Accepted risks and operator responsibilities

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
- **Image CVEs.** CI scans the image with Trivy. Debian findings without a fixed package
  version are ignored, because they cannot be patched by rebuilding. Dependabot keeps the digest
  current, but it never moves to the next Debian release; change the tag when one comes out.
- **Network-level egress filtering** is the operator's job. The README gives host firewall
  rules for `br-uptime`. They were not tested in this repository's CI.
- **Single process.** The in-memory rate limiter and scheduler assume exactly one uvicorn
  worker, which is the default.
