import ipaddress
import socket
import threading
import time

import pytest

from app import checker
from app.checker import TargetError, _is_public, normalize_target, probe


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("example.com", "https://example.com/"),
        ("http://Example.COM", "http://example.com/"),
        ("https://example.com:443/health?x=1", "https://example.com/health?x=1"),
        ("https://example.com:8443", "https://example.com:8443/"),
        ("https://bücher.de", "https://xn--bcher-kva.de/"),
        ("https://example.com/#frag", "https://example.com/"),
        ("1.1.1.1", "https://1.1.1.1/"),
    ],
)
def test_normalize_valid(raw, expected):
    assert normalize_target(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "ftp://example.com",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "https://user:pass@example.com",
        "localhost",
        "http://localhost:8000",
        "printer.local",
        "intranet",
        "127.0.0.1",
        "http://10.0.0.1",
        "http://169.254.169.254/latest/meta-data",
        "http://[::1]",
        "http://[::ffff:127.0.0.1]",
        "http://0.0.0.0",
        "https://example.com:0",
        "https://example.com:99999",
        "https://exa mple.com",
        "https://-bad-.com",
        "https://" + "a" * 300 + ".com",
    ],
)
def test_normalize_rejects(raw):
    with pytest.raises(TargetError):
        normalize_target(raw)


def test_private_allowed_when_enabled():
    assert normalize_target("http://10.0.0.5:8080", allow_private=True) == "http://10.0.0.5:8080/"


@pytest.mark.parametrize(
    ("ip", "public"),
    [
        ("8.8.8.8", True),
        ("2606:4700:4700::1111", True),
        ("127.0.0.1", False),
        ("10.1.2.3", False),
        ("172.16.0.1", False),
        ("192.168.1.1", False),
        ("100.64.0.1", False),
        ("169.254.169.254", False),
        ("::1", False),
        ("fd00::1", False),
        ("fe80::1", False),
        ("::ffff:10.0.0.1", False),
        ("64:ff9b::a00:1", False),  # NAT64 of 10.0.0.1
        ("64:ff9b::808:808", True),  # NAT64 of 8.8.8.8
        ("224.0.0.1", False),
        ("::7f00:1", False),  # IPv4-compatible 127.0.0.1
        ("::ffff:0:7f00:1", False),  # IPv4-translated 127.0.0.1
        ("fec0::1", False),  # deprecated site-local
        ("192.0.0.192", False),  # Oracle cloud metadata
        ("2002:7f00:1::", False),  # 6to4 of 127.0.0.1
        ("2002:808:808::", True),  # 6to4 of 8.8.8.8
        ("2001:0:4136:e378:8000:63bf:3fff:fdd2", False),  # Teredo
        ("64:ff9b:1::1", False),  # local-use NAT64
        ("198.18.0.1", False),  # benchmarking
        ("240.0.0.1", False),
    ],
)
def test_is_public(ip, public):
    assert _is_public(ipaddress.ip_address(ip)) is public


@pytest.mark.parametrize(
    "raw",
    [
        "http://１２７．０．０．１",  # fullwidth 127.0.0.1
        "http://127.1",
        "http://0x7f.1",
        "http://2130706433",
    ],
)
def test_normalize_rejects_ip_tricks(raw):
    with pytest.raises(TargetError):
        normalize_target(raw)


def test_port_allowlist():
    ports = frozenset({80, 443})
    assert normalize_target("http://example.com", allowed_ports=ports) == "http://example.com/"
    with pytest.raises(TargetError, match="Port 22 is not allowed"):
        normalize_target("http://example.com:22", allowed_ports=ports)
    with pytest.raises(TargetError):
        normalize_target("https://example.com:8443", allowed_ports=ports)


def test_stored_url_revalidated_at_probe_time(monkeypatch):
    called = []
    monkeypatch.setattr(checker, "_request_once", lambda *a: called.append(a) or (200, None))
    result = probe("http://example.com:6379/", 2, allowed_ports=frozenset({80, 443}))
    assert result.error == "Blocked: target not allowed" and not called
    assert probe("http://127.0.0.1/", 2).error == "Blocked: target not allowed"


def test_redirect_to_disallowed_port_is_blocked(monkeypatch):
    monkeypatch.setattr(
        checker, "_request_once", lambda url, timeout, allow_private: (302, "http://example.com:6379/")
    )
    result = probe("https://example.com/", 2, allowed_ports=frozenset({80, 443}))
    assert result.error == "Redirect to a disallowed URL"


def test_probe_blocks_dns_to_private(monkeypatch):
    # A public-looking name that resolves to an internal address (DNS rebinding).
    monkeypatch.setattr(
        checker.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("127.0.0.1", 80))]
    )
    result = probe("http://rebind.example.com/", 2)
    assert not result.ok
    assert result.error == "Blocked: resolves to a non-public address"


def test_probe_blocks_mixed_records(monkeypatch):
    monkeypatch.setattr(
        checker.socket,
        "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 443)), (2, 1, 6, "", ("10.0.0.1", 443))],
    )
    assert probe("https://mixed.example.com/", 2).error == "Blocked: resolves to a non-public address"


def test_probe_redirect_to_private_is_blocked(monkeypatch):
    monkeypatch.setattr(
        checker, "_request_once", lambda url, timeout, allow_private: (302, "http://127.0.0.1/admin")
    )
    result = probe("https://example.com/", 2)
    assert not result.ok and result.error == "Redirect to a disallowed URL"


def test_probe_http_error_is_down(monkeypatch):
    monkeypatch.setattr(checker, "_request_once", lambda url, timeout, allow_private: (503, None))
    result = probe("https://example.com/", 2)
    assert not result.ok and result.status_code == 503 and result.error == "HTTP 503"


def test_probe_enforces_total_deadline():
    """A server trickling bytes must not hold the check beyond its timeout."""
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def trickle():
        conn, _ = server.accept()
        conn.recv(1024)
        try:
            for _ in range(40):
                conn.sendall(b"H")
                time.sleep(0.2)
        except OSError:
            pass
        finally:
            conn.close()

    threading.Thread(target=trickle, daemon=True).start()
    started = time.monotonic()
    result = probe(f"http://127.0.0.1:{port}/", 1, allow_private=True)
    elapsed = time.monotonic() - started
    server.close()
    assert not result.ok and result.error == "Timeout"
    assert elapsed < 2.5


def test_probe_redirect_loop(monkeypatch):
    monkeypatch.setattr(
        checker, "_request_once", lambda url, timeout, allow_private: (301, "https://example.com/loop")
    )
    assert probe("https://example.com/", 2).error == "Too many redirects"
