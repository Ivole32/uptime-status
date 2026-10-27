"""HTTP(S) probing with SSRF protection.

Every request resolves the hostname itself, verifies that *all* resolved
addresses are public, and then connects to exactly that address (the IP is
pinned, so DNS rebinding between check and connect is not possible). Redirects
are followed manually and every hop is validated the same way.
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit

USER_AGENT = "UptimeStatus/1.0 (+uptime monitor)"
MAX_REDIRECTS = 5
MAX_URL_LENGTH = 2048
_BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home.arpa", ".intranet")

# Explicit deny lists, so protection does not depend on the Python version's
# idea of ipaddress.is_global (which changed in 3.12.4 / 3.13).
_V4_BLOCKED = tuple(
    ipaddress.ip_network(net)
    for net in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24",
        "192.88.99.0/24", "192.168.0.0/16", "192.175.48.0/24", "198.18.0.0/15",
        "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    )
)
_V6_BLOCKED = tuple(
    ipaddress.ip_network(net)
    for net in (
        "::/128", "::1/128", "64:ff9b:1::/48", "100::/64", "2001::/23", "2001:db8::/32",
        "3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8",
    )
)
# IPv6 ranges that carry an IPv4 address, which is checked instead.
_V4_IN_LOW_BITS = tuple(
    ipaddress.ip_network(net)
    for net in ("::ffff:0:0/96", "::ffff:0:0:0/96", "::/96", "64:ff9b::/96")
)
_6TO4 = ipaddress.ip_network("2002::/16")


class TargetError(ValueError):
    """The target URL is invalid or not allowed."""


@dataclass(frozen=True)
class ProbeResult:
    ok: bool
    response_ms: int | None
    status_code: int | None
    error: str | None


def normalize_target(
    raw: str, *, allow_private: bool = False, allowed_ports: frozenset[int] | None = None
) -> str:
    """Validate a user-supplied domain or URL and return a canonical URL.

    ``allowed_ports`` of None permits any port.
    """
    raw = (raw or "").strip()
    if not raw or len(raw) > MAX_URL_LENGTH:
        raise TargetError("Enter a domain or URL (max 2048 characters)")
    if any(ch.isspace() or ord(ch) < 32 for ch in raw):
        raise TargetError("URL must not contain whitespace or control characters")
    if "://" not in raw:
        raw = "https://" + raw

    parts = urlsplit(raw)
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise TargetError("Only http and https URLs are supported")
    if parts.username is not None or parts.password is not None:
        raise TargetError("Credentials in URLs are not allowed")
    try:
        port = parts.port
    except ValueError as exc:
        raise TargetError("Invalid port") from exc
    if port == 0:
        raise TargetError("Invalid port")
    effective_port = port or (443 if scheme == "https" else 80)
    if allowed_ports is not None and effective_port not in allowed_ports:
        allowed = ", ".join(str(p) for p in sorted(allowed_ports))
        raise TargetError(f"Port {effective_port} is not allowed (allowed: {allowed})")

    host = (parts.hostname or "").rstrip(".")
    if not host:
        raise TargetError("URL has no hostname")

    literal = _parse_ip(host)
    ascii_host = ""
    if literal is None:
        try:
            ascii_host = host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise TargetError("Invalid hostname") from exc
        # IDNA maps e.g. fullwidth digits to ASCII, so check for an IP literal again.
        literal = _parse_ip(ascii_host)
    if literal is not None:
        if not allow_private and not _is_public(literal):
            raise TargetError("Private, loopback and reserved addresses are not allowed")
        host_out = f"[{literal.compressed}]" if literal.version == 6 else literal.compressed
    else:
        labels = ascii_host.split(".")
        if len(ascii_host) > 253 or not all(
            0 < len(label) <= 63 and label.replace("-", "").isalnum() and not label.startswith("-")
            for label in labels
        ):
            raise TargetError("Invalid hostname")
        # Shorthand IPv4 forms like 127.1 or 0x7f.1 are not hostnames.
        if labels[-1].isdigit() or any(label.startswith("0x") for label in labels):
            raise TargetError("Invalid hostname")
        if not allow_private and (
            "." not in ascii_host
            or ascii_host == "localhost"
            or ascii_host.endswith(_BLOCKED_SUFFIXES)
        ):
            raise TargetError("Enter a public domain name")
        host_out = ascii_host

    default_port = 443 if scheme == "https" else 80
    netloc = host_out if port in (None, default_port) else f"{host_out}:{port}"
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def _parse_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host.strip("[]").split("%", 1)[0])
    except ValueError:
        return None


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    if any(ip in net for net in _V4_IN_LOW_BITS):
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip in _6TO4:
        return ipaddress.IPv4Address((int(ip) >> 80) & 0xFFFFFFFF)
    return None


def _is_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if ip.version == 6:
        if any(ip in net for net in _V6_BLOCKED):
            return False
        embedded = _embedded_ipv4(ip)
        if embedded is not None:
            return _is_public(embedded)
    elif any(ip in net for net in _V4_BLOCKED):
        return False
    return ip.is_global and not ip.is_multicast


def resolve(host: str, port: int, *, allow_private: bool) -> str:
    """Resolve host and return one validated IP to connect to."""
    literal = _parse_ip(host)
    if literal is not None:
        candidates = [literal]
    else:
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except (socket.gaierror, UnicodeError) as exc:
            raise _ProbeError("DNS resolution failed") from exc
        candidates = []
        for info in infos:
            ip = _parse_ip(str(info[4][0]))
            if ip is not None and ip not in candidates:
                candidates.append(ip)
    if not candidates:
        raise _ProbeError("DNS resolution failed")
    if not allow_private and not all(_is_public(ip) for ip in candidates):
        raise _ProbeError("Blocked: resolves to a non-public address")
    # Prefer IPv4 for broad container compatibility.
    candidates.sort(key=lambda ip: ip.version)
    return candidates[0].compressed


class _ProbeError(Exception):
    """A failure with a short, safe-to-display message."""


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, ip: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._pinned_ip = ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, ip: str, timeout: float, context: ssl.SSLContext) -> None:
        super().__init__(host, port, timeout=timeout, context=context)
        self._pinned_ip = ip
        self._tls_context = context

    def connect(self) -> None:
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # SNI and certificate validation use the real hostname, not the IP.
        self.sock = self._tls_context.wrap_socket(sock, server_hostname=self.host)


def _tls_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


_TLS = _tls_context()


def _request_once(url: str, timeout: float, allow_private: bool) -> tuple[int, str | None]:
    parts = urlsplit(url)
    host = parts.hostname or ""
    https = parts.scheme == "https"
    port = parts.port or (443 if https else 80)
    ip = resolve(host, port, allow_private=allow_private)
    conn: http.client.HTTPConnection
    if https:
        conn = _PinnedHTTPSConnection(host, port, ip, timeout, _TLS)
    else:
        conn = _PinnedHTTPConnection(host, port, ip, timeout)
    target = parts.path or "/"
    if parts.query:
        target += "?" + parts.query
    # Socket timeouts apply per operation, so a server trickling bytes could
    # otherwise hold this thread far beyond the deadline. The watchdog closes
    # the socket once the total time budget is spent.
    watchdog = threading.Timer(timeout, _abort, args=(conn,))
    watchdog.daemon = True
    watchdog.start()
    try:
        conn.request(
            "GET",
            target,
            headers={"User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"},
        )
        response = conn.getresponse()
        location = response.getheader("Location")
        return response.status, location
    except (OSError, http.client.HTTPException) as exc:
        if not watchdog.is_alive():
            raise TimeoutError from exc
        raise
    finally:
        watchdog.cancel()
        conn.close()


def _abort(conn: http.client.HTTPConnection) -> None:
    sock = conn.sock
    if sock is not None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass


def _classify(exc: BaseException) -> str:
    if isinstance(exc, _ProbeError):
        return str(exc)
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "Timeout"
    if isinstance(exc, ssl.SSLCertVerificationError):
        return "TLS certificate invalid"
    if isinstance(exc, ssl.SSLError):
        return "TLS handshake failed"
    if isinstance(exc, ConnectionRefusedError):
        return "Connection refused"
    if isinstance(exc, ConnectionResetError):
        return "Connection reset"
    if isinstance(exc, http.client.HTTPException):
        return "Invalid HTTP response"
    if isinstance(exc, OSError):
        return "Connection failed"
    return "Check failed"


def probe(
    url: str,
    timeout: float,
    *,
    allow_private: bool = False,
    allowed_ports: frozenset[int] | None = None,
) -> ProbeResult:
    """Request ``url`` (following validated redirects) and time the response."""
    deadline = time.monotonic() + timeout
    started = time.perf_counter()
    try:
        # Re-validate stored URLs: the policy (ports, private targets) may have
        # been tightened since the monitor was saved.
        try:
            current = normalize_target(url, allow_private=allow_private, allowed_ports=allowed_ports)
        except TargetError as exc:
            raise _ProbeError("Blocked: target not allowed") from exc
        for _ in range(MAX_REDIRECTS + 1):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _ProbeError("Timeout")
            status_code, location = _request_once(current, remaining, allow_private)
            if status_code in (301, 302, 303, 307, 308) and location:
                try:
                    current = normalize_target(
                        urljoin(current, location),
                        allow_private=allow_private,
                        allowed_ports=allowed_ports,
                    )
                except TargetError as exc:
                    raise _ProbeError("Redirect to a disallowed URL") from exc
                continue
            elapsed = int((time.perf_counter() - started) * 1000)
            if status_code < 400:
                return ProbeResult(True, elapsed, status_code, None)
            return ProbeResult(False, elapsed, status_code, f"HTTP {status_code}")
        raise _ProbeError("Too many redirects")
    except Exception as exc:  # noqa: BLE001 - every failure becomes a "down" result
        return ProbeResult(False, None, None, _classify(exc))
