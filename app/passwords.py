"""Password hashing with scrypt (standard library only).

Hash format (PHC-like)::

    $scrypt$ln=15,r=8,p=1$<base64 salt>$<base64 hash>

This module must stay free of third-party imports so ``python -m app.cli``
works on any machine with Python 3.11+ and nothing else installed.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

DEFAULT_LOG_N = 15  # N = 2**15 -> 32 MiB of memory per hash with r=8
DEFAULT_R = 8
DEFAULT_P = 1
SALT_BYTES = 16
KEY_BYTES = 32
MAX_PASSWORD_BYTES = 1024
_MAX_LOG_N = 20
_MAX_MEM = 1100 * 1024 * 1024


class InvalidHashError(ValueError):
    pass


def _b64encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii").rstrip("=")


def _b64decode(text: str) -> bytes:
    return base64.b64decode(text + "=" * (-len(text) % 4), validate=True)


def _scrypt(password: bytes, salt: bytes, log_n: int, r: int, p: int, dklen: int) -> bytes:
    return hashlib.scrypt(password, salt=salt, n=2**log_n, r=r, p=p, dklen=dklen, maxmem=_MAX_MEM)


def hash_password(password: str, *, log_n: int = DEFAULT_LOG_N) -> str:
    raw = password.encode("utf-8")
    if not raw:
        raise ValueError("Password must not be empty")
    if len(raw) > MAX_PASSWORD_BYTES:
        raise ValueError(f"Password must be at most {MAX_PASSWORD_BYTES} bytes")
    salt = secrets.token_bytes(SALT_BYTES)
    digest = _scrypt(raw, salt, log_n, DEFAULT_R, DEFAULT_P, KEY_BYTES)
    return f"$scrypt$ln={log_n},r={DEFAULT_R},p={DEFAULT_P}${_b64encode(salt)}${_b64encode(digest)}"


def parse_hash(encoded: str) -> tuple[int, int, int, bytes, bytes]:
    parts = encoded.strip().split("$")
    if len(parts) != 5 or parts[0] != "" or parts[1] != "scrypt":
        raise InvalidHashError("Not a $scrypt$ hash")
    try:
        params = dict(item.split("=", 1) for item in parts[2].split(","))
        log_n, r, p = int(params["ln"]), int(params["r"]), int(params["p"])
        salt, digest = _b64decode(parts[3]), _b64decode(parts[4])
    except (KeyError, ValueError) as exc:
        raise InvalidHashError("Malformed scrypt hash") from exc
    if not (10 <= log_n <= _MAX_LOG_N and 1 <= r <= 32 and 1 <= p <= 16):
        raise InvalidHashError("scrypt parameters out of range")
    if len(salt) < 8 or len(digest) < 16:
        raise InvalidHashError("scrypt salt or hash too short")
    return log_n, r, p, salt, digest


def verify_password(password: str, encoded: str) -> bool:
    log_n, r, p, salt, expected = parse_hash(encoded)
    raw = password.encode("utf-8")
    if not raw or len(raw) > MAX_PASSWORD_BYTES:
        # Still burn the same amount of work so timing does not reveal the reason.
        _scrypt(b"\0", salt, log_n, r, p, len(expected))
        return False
    actual = _scrypt(raw, salt, log_n, r, p, len(expected))
    return hmac.compare_digest(actual, expected)
