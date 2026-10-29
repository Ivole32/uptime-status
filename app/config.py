"""Runtime configuration, read once from environment variables (prefix ``UPTIME_``)."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path


def _env(name: str, default: str) -> str:
    return os.environ.get(f"UPTIME_{name}", default).strip()


def _bool(name: str, default: bool) -> bool:
    value = _env(name, "true" if default else "false").lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"UPTIME_{name} must be a boolean, got {value!r}")


def _int(name: str, default: int, minimum: int, maximum: int) -> int:
    value = int(_env(name, str(default)))
    if not minimum <= value <= maximum:
        raise ValueError(f"UPTIME_{name} must be between {minimum} and {maximum}")
    return value


def _list(name: str) -> list[str]:
    return [item.strip() for item in _env(name, "").split(",") if item.strip()]


def _ports(name: str, default: str) -> frozenset[int] | None:
    """Comma-separated port list; "*" means any port (returns None)."""
    raw = _env(name, default)
    if raw == "*":
        return None
    ports = frozenset(int(p) for p in raw.split(",") if p.strip())
    if not ports or not all(1 <= p <= 65535 for p in ports):
        raise ValueError(f"UPTIME_{name} must be '*' or a list of ports 1-65535")
    return ports


def _networks(name: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    """Comma-separated IPs or CIDRs."""
    try:
        return tuple(ipaddress.ip_network(item, strict=False) for item in _list(name))
    except ValueError as exc:
        raise ValueError(f"UPTIME_{name} must be a list of IP addresses or CIDRs: {exc}") from exc


@dataclass(frozen=True)
class Settings:
    database_url: str
    credentials_file: Path
    cookie_secure: bool
    session_ttl_hours: int
    allowed_hosts: list[str] = field(default_factory=list)
    allow_private_targets: bool = False
    allowed_ports: frozenset[int] | None = frozenset({80, 443, 8080, 8443})
    blocked_networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
    scheduler_enabled: bool = True
    check_concurrency: int = 10
    check_retries: int = 1
    raw_retention_days: int = 30
    max_monitors: int = 200
    public_cache_seconds: int = 10
    public_refresh_seconds: int = 30
    login_max_attempts: int = 5
    login_window_minutes: int = 15
    enable_api_docs: bool = False

    @property
    def session_cookie_name(self) -> str:
        # The __Host- prefix forces Secure, Path=/ and no Domain attribute in browsers.
        return "__Host-uptime_session" if self.cookie_secure else "uptime_session"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings(
        database_url=_env("DATABASE_URL", "sqlite:////data/uptime.db"),
        credentials_file=Path(_env("CREDENTIALS_FILE", "/config/admin.toml")),
        cookie_secure=_bool("COOKIE_SECURE", True),
        session_ttl_hours=_int("SESSION_TTL_HOURS", 12, 1, 24 * 30),
        allowed_hosts=_list("ALLOWED_HOSTS"),
        allow_private_targets=_bool("ALLOW_PRIVATE_TARGETS", False),
        allowed_ports=_ports("ALLOWED_PORTS", "80,443,8080,8443"),
        blocked_networks=_networks("BLOCKED_NETWORKS"),
        scheduler_enabled=_bool("SCHEDULER_ENABLED", True),
        check_concurrency=_int("CHECK_CONCURRENCY", 10, 1, 100),
        check_retries=_int("CHECK_RETRIES", 1, 0, 5),
        raw_retention_days=_int("RAW_RETENTION_DAYS", 30, 2, 3650),
        max_monitors=_int("MAX_MONITORS", 200, 1, 10000),
        public_cache_seconds=_int("PUBLIC_CACHE_SECONDS", 10, 0, 300),
        public_refresh_seconds=_int("PUBLIC_REFRESH_SECONDS", 30, 5, 3600),
        login_max_attempts=_int("LOGIN_MAX_ATTEMPTS", 5, 1, 100),
        login_window_minutes=_int("LOGIN_WINDOW_MINUTES", 15, 1, 1440),
        enable_api_docs=_bool("ENABLE_API_DOCS", False),
    )
