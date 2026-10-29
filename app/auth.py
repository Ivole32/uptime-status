"""Single-admin authentication backed by a TOML credentials file.

The credentials file (``UPTIME_CREDENTIALS_FILE``) looks like::

    username = "admin"
    password_hash = "$scrypt$ln=15,r=8,p=1$...$..."

It is re-read whenever its content changes, so editing it takes effect without
a restart (mount its directory, not the file itself: a single-file bind mount
never sees editors that save by renaming). Every session is bound to a
fingerprint of the current credentials:
changing the username or password hash signs out all existing sessions.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import secrets
import threading
import time
import tomllib
from collections import deque
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from fastapi import Depends, HTTPException, Request, Response, status
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from .config import Settings, get_settings
from .db import get_db, utcnow
from .models import AdminSession
from .passwords import InvalidHashError, hash_password, parse_hash, verify_password

log = logging.getLogger("uptime.auth")

MAX_USERNAME_LENGTH = 64
CSRF_HEADER = "X-CSRF-Token"


@dataclass(frozen=True)
class Credentials:
    username: str
    password_hash: str

    @property
    def fingerprint(self) -> str:
        material = f"{self.username}\0{self.password_hash}".encode()
        return hashlib.sha256(material).hexdigest()


class _CredentialStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cache: tuple[Path, bytes, Credentials | None] | None = None

    def load(self, path: Path) -> Credentials | None:
        # Keyed on the content, not on mtime/size: a new hash always has the same
        # length, and copies can preserve the old mtime. The file is tiny.
        try:
            raw = path.read_bytes()
        except OSError:
            log.error("Credentials file %s is missing; admin login is disabled", path)
            return None
        digest = hashlib.sha256(raw).digest()
        with self._lock:
            if self._cache and self._cache[:2] == (path, digest):
                return self._cache[2]
            creds = self._parse(path, raw)
            self._cache = (path, digest, creds)
        if creds is not None:
            # Lets operators confirm in the logs that a password change took effect.
            log.info("Loaded admin credentials from %s (fingerprint %s)", path, creds.fingerprint[:12])
        return creds

    @staticmethod
    def _parse(path: Path, raw: bytes) -> Credentials | None:
        try:
            data = tomllib.loads(raw.decode("utf-8"))
            username = str(data["username"]).strip()
            password_hash = str(data["password_hash"]).strip()
            parse_hash(password_hash)
        except (UnicodeDecodeError, tomllib.TOMLDecodeError, KeyError, InvalidHashError) as exc:
            log.error("Credentials file %s is invalid (%s); admin login is disabled", path, exc)
            return None
        if not username or len(username) > MAX_USERNAME_LENGTH:
            log.error("Credentials file %s has an invalid username", path)
            return None
        return Credentials(username=username, password_hash=password_hash)


credential_store = _CredentialStore()

# Used to equalise timing when no valid credentials are configured.
_DUMMY_HASH = hash_password(secrets.token_urlsafe(16))

# scrypt needs 32 MiB+ per call; cap concurrent verifications to bound memory.
_hash_slots = threading.BoundedSemaphore(2)


class LoginBusy(Exception):
    """All hash slots are in use; the caller should retry shortly."""


def check_login(settings: Settings, username: str, password: str) -> Credentials | None:
    # Never queue: a burst of logins must not tie up worker threads that the
    # public page and admin API also need.
    if not _hash_slots.acquire(blocking=False):
        raise LoginBusy
    try:
        creds = credential_store.load(settings.credentials_file)
        if creds is None:
            verify_password(password, _DUMMY_HASH)
            return None
        # Compare fixed-length digests so the username length does not leak via timing.
        user_ok = hmac.compare_digest(
            hashlib.sha256(username.encode("utf-8")).digest(),
            hashlib.sha256(creds.username.encode("utf-8")).digest(),
        )
        password_ok = verify_password(password, creds.password_hash)
    finally:
        _hash_slots.release()
    return creds if (user_ok and password_ok) else None


class LoginRateLimiter:
    """Sliding-window limiter on login attempts per client.

    An attempt is reserved atomically *before* the password is checked, so a
    burst of concurrent requests cannot exceed the limit. A successful login
    clears the client's bucket. There is deliberately no global cap: it would
    let anyone lock the real admin out.
    """

    MAX_TRACKED_CLIENTS = 10_000

    def __init__(self, max_attempts: int, window_seconds: int) -> None:
        self.max_attempts = max_attempts
        self.window = window_seconds
        self._lock = threading.Lock()
        self._per_client: dict[str, deque[float]] = {}

    def _prune(self, bucket: deque[float], now: float) -> None:
        while bucket and bucket[0] <= now - self.window:
            bucket.popleft()

    def reserve(self, client: str) -> tuple[float | None, int]:
        """Reserve an attempt. Returns (token, 0) or (None, retry_after_seconds)."""
        now = time.monotonic()
        with self._lock:
            bucket = self._per_client.get(client)
            if bucket is None:
                if len(self._per_client) >= self.MAX_TRACKED_CLIENTS:
                    self._evict(now)
                bucket = self._per_client.setdefault(client, deque())
            self._prune(bucket, now)
            if len(bucket) >= self.max_attempts:
                return None, int(bucket[0] + self.window - now) + 1
            bucket.append(now)
            return now, 0

    def release(self, client: str, token: float) -> None:
        """Give back a reserved attempt that was never evaluated."""
        with self._lock:
            bucket = self._per_client.get(client)
            if bucket is not None and token in bucket:
                bucket.remove(token)

    def record_success(self, client: str) -> None:
        with self._lock:
            self._per_client.pop(client, None)

    def _evict(self, now: float) -> None:
        for key in list(self._per_client):
            bucket = self._per_client[key]
            self._prune(bucket, now)
            if not bucket:
                del self._per_client[key]
        while len(self._per_client) >= self.MAX_TRACKED_CLIENTS:
            self._per_client.pop(next(iter(self._per_client)))


_settings = get_settings()
login_limiter = LoginRateLimiter(
    max_attempts=_settings.login_max_attempts,
    window_seconds=_settings.login_window_minutes * 60,
)


def client_ip(request: Request) -> str:
    # uvicorn rewrites request.client from X-Forwarded-For only for trusted
    # proxies (--forwarded-allow-ips), so this cannot be spoofed by clients.
    return request.client.host if request.client else "unknown"


def rate_limit_key(ip: str) -> str:
    """IPv6 clients are grouped by /64, since one host usually owns a whole /64."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if addr.version == 6:
        if addr.ipv4_mapped is not None:
            return str(addr.ipv4_mapped)
        return str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return str(addr)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("ascii", "ignore")).hexdigest()


def create_session(db: Session, settings: Settings, creds: Credentials, response: Response) -> str:
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    now = utcnow()
    db.execute(delete(AdminSession).where(AdminSession.expires_at <= now))
    db.add(
        AdminSession(
            token_hash=_hash_token(token),
            csrf_token=csrf,
            credential_fingerprint=creds.fingerprint,
            created_at=now,
            expires_at=now + timedelta(hours=settings.session_ttl_hours),
        )
    )
    db.commit()
    response.set_cookie(
        key=settings.session_cookie_name,
        value=token,
        max_age=settings.session_ttl_hours * 3600,
        path="/",
        secure=settings.cookie_secure,
        httponly=True,
        samesite="strict",
    )
    return csrf


def clear_session_cookie(settings: Settings, response: Response) -> None:
    response.delete_cookie(
        key=settings.session_cookie_name,
        path="/",
        secure=settings.cookie_secure,
        httponly=True,
        samesite="strict",
    )


def _lookup_session(request: Request, db: Session, settings: Settings) -> AdminSession | None:
    token = request.cookies.get(settings.session_cookie_name)
    if not token or len(token) > 128:
        return None
    session = db.scalar(select(AdminSession).where(AdminSession.token_hash == _hash_token(token)))
    if session is None:
        return None
    creds = credential_store.load(settings.credentials_file)
    valid = (
        session.expires_at > utcnow()
        and creds is not None
        and hmac.compare_digest(session.credential_fingerprint, creds.fingerprint)
    )
    if not valid:
        db.delete(session)
        db.commit()
        return None
    return session


def optional_session(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AdminSession | None:
    return _lookup_session(request, db, settings)


def require_admin(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AdminSession:
    session = _lookup_session(request, db, settings)
    if session is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not authenticated")
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        sent = request.headers.get(CSRF_HEADER, "")
        if not sent or not hmac.compare_digest(sent.encode(), session.csrf_token.encode()):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Invalid CSRF token")
    return session
