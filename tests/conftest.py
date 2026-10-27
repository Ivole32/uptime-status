"""Test setup: isolated SQLite database and credentials file, scheduler disabled."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

_TMP = Path(tempfile.mkdtemp(prefix="uptime-test-"))
os.environ.update(
    {
        "UPTIME_DATABASE_URL": f"sqlite:///{(_TMP / 'test.db').as_posix()}",
        "UPTIME_CREDENTIALS_FILE": str(_TMP / "admin.toml"),
        "UPTIME_COOKIE_SECURE": "false",
        "UPTIME_SCHEDULER_ENABLED": "false",
        "UPTIME_PUBLIC_CACHE_SECONDS": "0",
    }
)

from fastapi.testclient import TestClient  # noqa: E402

from app.__main__ import migrate  # noqa: E402
from app.auth import login_limiter  # noqa: E402
from app.db import engine  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Base  # noqa: E402
from app.passwords import hash_password  # noqa: E402

USERNAME = "admin"
PASSWORD = "correct horse battery staple"
CREDENTIALS_FILE = _TMP / "admin.toml"


def write_credentials(username: str = USERNAME, password: str = PASSWORD) -> None:
    CREDENTIALS_FILE.write_text(
        f'username = "{username}"\npassword_hash = "{hash_password(password, log_n=10)}"\n',
        encoding="utf-8",
    )
    # Bump the mtime so the credential cache notices even on coarse filesystems.
    stat = CREDENTIALS_FILE.stat()
    os.utime(CREDENTIALS_FILE, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))


@pytest.fixture(autouse=True)
def _fresh_state():
    Base.metadata.drop_all(engine)
    with engine.begin() as conn:
        conn.exec_driver_sql("DROP TABLE IF EXISTS alembic_version")
    migrate()
    write_credentials()
    login_limiter._per_client.clear()
    yield


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def admin(client):
    res = client.post("/api/auth/login", json={"username": USERNAME, "password": PASSWORD})
    assert res.status_code == 200, res.text
    client.headers["X-CSRF-Token"] = res.json()["csrf_token"]
    return client
