import dataclasses
import os
from datetime import timedelta

from fastapi.testclient import TestClient

from app.checker import ProbeResult
from app.config import get_settings
from app.db import SessionLocal, utcnow
from app.main import app
from app.models import AdminSession, Incident, Monitor
from app.scheduler import record_result

from .conftest import CREDENTIALS_FILE, PASSWORD, USERNAME, write_credentials

MONITOR = {"name": "Website", "url": "example.com", "interval_seconds": 60, "timeout_seconds": 10}


def test_public_status_empty(client):
    res = client.get("/api/status")
    assert res.status_code == 200
    body = res.json()
    assert body["monitors"] == [] and body["overall_status"] == "unknown"


def test_pages_served(client):
    assert client.get("/").status_code == 200
    assert client.get("/admin").headers["x-robots-tag"] == "noindex, nofollow"
    assert client.get("/static/js/status.js").status_code == 200
    assert client.get("/static/../app/config.py").status_code == 404


def test_security_headers(client):
    res = client.get("/")
    csp = res.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert res.headers["x-content-type-options"] == "nosniff"
    assert res.headers["x-frame-options"] == "DENY"
    assert res.headers["referrer-policy"] == "no-referrer"


def test_api_docs_disabled(client):
    assert client.get("/api/docs").status_code == 404
    assert client.get("/api/openapi.json").status_code == 404


def test_admin_requires_login(client):
    assert client.get("/api/admin/monitors").status_code == 401
    assert client.post("/api/admin/monitors", json=MONITOR).status_code == 401
    assert client.get("/api/admin/settings").status_code == 401
    assert client.get("/api/auth/me").json() == {"authenticated": False}


def test_login_wrong_password_and_username(client):
    bad_pw = client.post("/api/auth/login", json={"username": USERNAME, "password": "nope"})
    bad_user = client.post("/api/auth/login", json={"username": "root", "password": PASSWORD})
    assert bad_pw.status_code == bad_user.status_code == 401
    assert bad_pw.json() == bad_user.json()  # no username enumeration


def test_login_rate_limited(client):
    for _ in range(5):
        client.post("/api/auth/login", json={"username": USERNAME, "password": "wrong"})
    res = client.post("/api/auth/login", json={"username": USERNAME, "password": PASSWORD})
    assert res.status_code == 429
    assert int(res.headers["retry-after"]) > 0


def test_rate_limit_reservation_is_atomic():
    from app.auth import LoginRateLimiter

    limiter = LoginRateLimiter(max_attempts=3, window_seconds=60)
    tokens = [limiter.reserve("1.2.3.4")[0] for _ in range(3)]
    assert all(t is not None for t in tokens)
    token, wait = limiter.reserve("1.2.3.4")
    assert token is None and wait > 0  # refused before any password is checked
    limiter.release("1.2.3.4", tokens[0])
    assert limiter.reserve("1.2.3.4")[0] is not None


def test_ipv6_clients_grouped_by_64():
    from app.auth import rate_limit_key

    assert rate_limit_key("2001:db8:1:2::1") == rate_limit_key("2001:db8:1:2:ffff::9")
    assert rate_limit_key("2001:db8:1:2::1") != rate_limit_key("2001:db8:1:3::1")
    assert rate_limit_key("::ffff:203.0.113.5") == "203.0.113.5"
    assert rate_limit_key("203.0.113.5") == "203.0.113.5"
    assert rate_limit_key("testclient") == "testclient"


def test_login_busy_does_not_block_or_count(client, monkeypatch):
    import threading

    from app import auth

    monkeypatch.setattr(auth, "_hash_slots", threading.BoundedSemaphore(1))
    auth._hash_slots.acquire()
    try:
        for _ in range(8):
            res = client.post("/api/auth/login", json={"username": USERNAME, "password": PASSWORD})
            assert res.status_code == 429 and res.headers["retry-after"] == "1"
    finally:
        auth._hash_slots.release()
    # Busy rejections were refunded, so a real login still works.
    assert client.post("/api/auth/login", json={"username": USERNAME, "password": PASSWORD}).status_code == 200


def test_password_whitespace_is_preserved(client):
    write_credentials(password="  spaced password  ")
    ok = client.post("/api/auth/login", json={"username": f" {USERNAME} ", "password": "  spaced password  "})
    assert ok.status_code == 200
    stripped = client.post("/api/auth/login", json={"username": USERNAME, "password": "spaced password"})
    assert stripped.status_code == 401


def test_no_slash_redirect_with_spoofed_host(client):
    res = client.get("/api/status/", headers={"Host": "evil.example"}, follow_redirects=False)
    assert res.status_code == 404 and "location" not in res.headers


def test_session_cookie_flags(client):
    res = client.post("/api/auth/login", json={"username": USERNAME, "password": PASSWORD})
    cookie = res.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie and "path=/" in cookie
    assert res.headers["cache-control"] == "no-store"


def test_session_token_not_stored_in_plaintext(client):
    client.post("/api/auth/login", json={"username": USERNAME, "password": PASSWORD})
    token = client.cookies.get("uptime_session")
    with SessionLocal() as db:
        stored = [s.token_hash for s in db.query(AdminSession)]
    assert token and token not in stored and len(stored[0]) == 64


def test_csrf_required(admin):
    token = admin.headers.pop("X-CSRF-Token")
    assert admin.post("/api/admin/monitors", json=MONITOR).status_code == 403
    admin.headers["X-CSRF-Token"] = "forged"
    assert admin.post("/api/admin/monitors", json=MONITOR).status_code == 403
    admin.headers["X-CSRF-Token"] = token
    assert admin.post("/api/admin/monitors", json=MONITOR).status_code == 201


def test_cross_origin_write_blocked(admin):
    res = admin.post("/api/admin/monitors", json=MONITOR, headers={"Origin": "https://evil.example"})
    assert res.status_code == 403
    res = admin.post("/api/admin/monitors", json=MONITOR, headers={"Sec-Fetch-Site": "cross-site"})
    assert res.status_code == 403
    res = admin.post("/api/admin/monitors", json=MONITOR, headers={"Origin": "http://testserver"})
    assert res.status_code == 201


def test_non_json_write_rejected(admin):
    res = admin.post(
        "/api/admin/monitors",
        content=b"name=x",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert res.status_code == 415


def test_body_size_limit(admin):
    res = admin.post("/api/admin/monitors", json={**MONITOR, "description": "x" * 70_000})
    assert res.status_code == 413


def test_monitor_crud(admin):
    res = admin.post("/api/admin/monitors", json={**MONITOR, "description": "Main site"})
    assert res.status_code == 201, res.text
    created = res.json()
    assert created["url"] == "https://example.com/" and created["status"] == "pending"

    updated = admin.put(f"/api/admin/monitors/{created['id']}", json={**MONITOR, "name": "Renamed"})
    assert updated.status_code == 200 and updated.json()["name"] == "Renamed"

    assert admin.post(f"/api/admin/monitors/{created['id']}/check").status_code == 202
    assert admin.delete(f"/api/admin/monitors/{created['id']}").status_code == 204
    assert admin.get("/api/admin/monitors").json() == []
    assert admin.delete("/api/admin/monitors/9999").status_code == 404
    assert admin.delete(f"/api/admin/monitors/{10**30}").status_code == 422
    assert admin.get("/api/admin/monitors/0/checks").status_code == 422


def test_monitor_validation(admin):
    for url in ["localhost", "http://127.0.0.1", "file:///etc/passwd", "http://169.254.169.254"]:
        res = admin.post("/api/admin/monitors", json={**MONITOR, "url": url})
        assert res.status_code == 422, url
        assert url not in res.text  # input is never echoed back
    bad = [
        {"timeout_seconds": 60, "interval_seconds": 30},
        {"interval_seconds": 1},
        {"unknown_field": True},
        {"name": "   "},
        {"name": "x" * 101},
    ]
    for override in bad:
        assert admin.post("/api/admin/monitors", json={**MONITOR, **override}).status_code == 422, override


def test_public_hides_private_data(admin):
    hidden = admin.post("/api/admin/monitors", json={**MONITOR, "name": "Internal", "is_public": False}).json()
    shown = admin.post("/api/admin/monitors", json={**MONITOR, "name": "Public"}).json()
    linked = admin.post(
        "/api/admin/monitors", json={**MONITOR, "name": "Linked", "url": "example.org", "show_url": True}
    ).json()
    body = admin.get("/api/status").json()
    names = {m["name"]: m for m in body["monitors"]}
    assert "Internal" not in names and hidden["id"] not in {m["id"] for m in body["monitors"]}
    assert names["Public"]["url"] is None and shown["id"] == names["Public"]["id"]
    assert names["Linked"]["url"] == linked["url"]
    assert "interval_seconds" not in names["Public"]


def test_hidden_urls_never_reach_anonymous_visitors(admin, monkeypatch):
    """Operators keep private IPs and tokens in monitor URLs; only show_url may expose them."""
    settings = dataclasses.replace(get_settings(), allow_private_targets=True, allowed_ports=None)
    monkeypatch.setattr("app.schemas.get_settings", lambda: settings)
    secret_monitors = [
        {"name": "Router", "url": "http://192.168.178.1:8080/admin?token=SECRET-QUERY-123"},
        {"name": "NAS", "url": "http://10.13.37.42/", "description": "Storage"},
        {"name": "Internal host", "url": "http://secret-internal-host.corp.example/"},
        {"name": "Hidden", "url": "http://172.20.99.7:9000/", "is_public": False},
    ]
    errors = ["Timeout", "DNS resolution failed", "HTTP 503", "Blocked: resolves to a non-public address"]
    ids = []
    for monitor, error in zip(secret_monitors, errors, strict=True):
        res = admin.post("/api/admin/monitors", json={**MONITOR, **monitor})
        assert res.status_code == 201, res.text
        ids.append(res.json()["id"])
        # Down with an open incident: the state that puts the most detail on the public page.
        record_result(ids[-1], ProbeResult(False, 5, 503 if error == "HTTP 503" else None, error))
    shown = admin.post("/api/admin/monitors", json={**MONITOR, "url": "example.org", "show_url": True})
    record_result(shown.json()["id"], ProbeResult(True, 5, 200, None))

    needles = ["192.168.178", "SECRET-QUERY", "token=", "/admin?", ":8080", "10.13.37", "secret-internal",
               "corp.example", "172.20.99", ":9000"]
    paths = ["/", "/admin", "/api/status", "/healthz", "/api/auth/me", "/api/admin/monitors",
             "/api/admin/incidents", "/api/admin/settings", f"/api/admin/monitors/{ids[0]}/checks",
             "/static/js/status.js", "/static/js/admin.js"]
    with TestClient(app) as anonymous:
        for path in paths:
            res = anonymous.get(path)
            seen = res.text + "".join(f"{k}: {v}\n" for k, v in res.headers.items())
            leaked = [n for n in needles if n in seen]
            assert not leaked, f"{path} exposes {leaked}"
        body = anonymous.get("/api/status").json()

    public = {m["name"]: m for m in body["monitors"]}
    assert "Hidden" not in public
    assert all(public[name]["url"] is None for name in ("Router", "NAS", "Internal host"))
    assert {m["url"] for m in body["monitors"]} == {None, "https://example.org/"}
    assert len(body["incidents"]["active"]) == 3  # the hidden monitor's incident is not listed


def test_results_incidents_and_uptime(admin):
    mid = admin.post("/api/admin/monitors", json=MONITOR).json()["id"]
    record_result(mid, ProbeResult(True, 120, 200, None))
    record_result(mid, ProbeResult(False, None, None, "Timeout"))
    record_result(mid, ProbeResult(False, None, 503, "HTTP 503"))

    body = admin.get("/api/status").json()
    assert body["overall_status"] == "major_outage"
    assert len(body["incidents"]["active"]) == 1
    assert body["incidents"]["active"][0]["error"] == "Service unreachable"

    record_result(mid, ProbeResult(True, 80, 200, None))
    body = admin.get("/api/status").json()
    monitor = body["monitors"][0]
    assert body["overall_status"] == "operational"
    assert body["incidents"]["active"] == [] and len(body["incidents"]["past"]) == 1
    assert monitor["uptime"]["24h"] == 50.0 and monitor["uptime"]["90d"] == 50.0
    assert monitor["days"][-1]["uptime"] == 50.0 and monitor["days"][-1]["avg_ms"] == 100
    assert len(monitor["days"]) == 90
    assert monitor["response_24h"][0]["ms"] == 100
    assert body["overall_days"][-1]["uptime"] == 50.0
    assert body["generated_at"].endswith("Z")

    checks = admin.get(f"/api/admin/monitors/{mid}/checks").json()
    assert len(checks) == 4 and checks[0]["ok"] is True

    incidents = admin.get("/api/admin/incidents").json()
    assert admin.delete(f"/api/admin/incidents/{incidents[0]['id']}").status_code == 204
    assert admin.get("/api/status").json()["incidents"]["past"] == []


def test_public_errors_are_coarse(admin):
    mid = admin.post("/api/admin/monitors", json=MONITOR).json()["id"]
    record_result(mid, ProbeResult(False, None, None, "Connection refused"))
    public = admin.get("/api/status").json()["incidents"]["active"][0]["error"]
    assert public == "Service unreachable"
    # The admin still sees the precise reason.
    assert admin.get("/api/admin/incidents").json()[0]["error"] == "Connection refused"


def test_stale_monitor_reported_unknown(admin):
    mid = admin.post("/api/admin/monitors", json=MONITOR).json()["id"]
    record_result(mid, ProbeResult(True, 50, 200, None))
    assert admin.get("/api/status").json()["monitors"][0]["status"] == "up"
    with SessionLocal() as db:
        db.get(Monitor, mid).last_checked_at = utcnow() - timedelta(hours=1)
        db.commit()
    body = admin.get("/api/status").json()
    assert body["monitors"][0]["status"] == "unknown"
    assert body["overall_status"] == "unknown"


def test_disallowed_port_rejected(admin):
    res = admin.post("/api/admin/monitors", json={**MONITOR, "url": "example.com:22"})
    assert res.status_code == 422


def test_record_result_for_deleted_monitor_is_ignored(admin):
    mid = admin.post("/api/admin/monitors", json=MONITOR).json()["id"]
    admin.delete(f"/api/admin/monitors/{mid}")
    record_result(mid, ProbeResult(True, 10, 200, None))  # must not raise


def test_deleting_monitor_cascades(admin):
    mid = admin.post("/api/admin/monitors", json=MONITOR).json()["id"]
    record_result(mid, ProbeResult(False, None, None, "Timeout"))
    admin.delete(f"/api/admin/monitors/{mid}")
    with SessionLocal() as db:
        assert db.query(Incident).count() == 0
        assert db.get(Monitor, mid) is None


def test_credential_change_revokes_sessions(admin):
    assert admin.get("/api/admin/monitors").status_code == 200
    write_credentials(username="newadmin")
    assert admin.get("/api/admin/monitors").status_code == 401
    res = admin.post("/api/auth/login", json={"username": "newadmin", "password": PASSWORD})
    assert res.status_code == 200


def test_password_change_detected_with_same_size_and_mtime(admin):
    """A new hash has the same length; copies can keep the old mtime. Content decides."""
    before = CREDENTIALS_FILE.stat()
    write_credentials(password="a different password")
    os.utime(CREDENTIALS_FILE, ns=(before.st_atime_ns, before.st_mtime_ns))
    after = CREDENTIALS_FILE.stat()
    assert (after.st_size, after.st_mtime_ns) == (before.st_size, before.st_mtime_ns)
    assert admin.get("/api/admin/monitors").status_code == 401
    res = admin.post("/api/auth/login", json={"username": USERNAME, "password": PASSWORD})
    assert res.status_code == 401


def test_non_utf8_credentials_file_disables_login(client):
    CREDENTIALS_FILE.write_bytes(b'username = "adm\xe9n"\npassword_hash = "x"\n')
    res = client.post("/api/auth/login", json={"username": USERNAME, "password": PASSWORD})
    assert res.status_code == 401


def test_outside_id_follows_userns_remap(tmp_path):
    from app.auth import _outside_id

    remapped = tmp_path / "remapped"
    remapped.write_text("         0     100000      65536\n", encoding="ascii")
    identity = tmp_path / "identity"
    identity.write_text("         0          0 4294967295\n", encoding="ascii")
    assert _outside_id(str(remapped), 10001) == 110001
    assert _outside_id(str(identity), 10001) == 10001
    assert _outside_id(str(remapped), 70000) is None  # outside the mapped range
    assert _outside_id(str(tmp_path / "absent"), 10001) is None


def test_unreadable_credentials_logged_as_permission_problem(client, monkeypatch, caplog):
    from pathlib import Path

    def deny(self):
        raise PermissionError(13, "Permission denied", str(self))

    monkeypatch.setattr(Path, "read_bytes", deny)
    monkeypatch.setattr("app.auth._ownership_hint", lambda path: "HINT")
    with caplog.at_level("ERROR", logger="uptime.auth"):
        res = client.post("/api/auth/login", json={"username": USERNAME, "password": PASSWORD})
    assert res.status_code == 401
    assert "not readable (permission denied)" in caplog.text and "HINT" in caplog.text
    assert "missing" not in caplog.text


def test_missing_credentials_file_logged_as_missing(client, caplog):
    CREDENTIALS_FILE.unlink()
    with caplog.at_level("ERROR", logger="uptime.auth"):
        client.post("/api/auth/login", json={"username": USERNAME, "password": PASSWORD})
    assert "is missing" in caplog.text and "permission" not in caplog.text


def test_missing_credentials_file_disables_login(client):
    CREDENTIALS_FILE.unlink()
    res = client.post("/api/auth/login", json={"username": USERNAME, "password": PASSWORD})
    assert res.status_code == 401


def test_expired_session_rejected(admin):
    with SessionLocal() as db:
        for s in db.query(AdminSession):
            s.expires_at = utcnow() - timedelta(seconds=1)
        db.commit()
    assert admin.get("/api/admin/monitors").status_code == 401


def test_logout(admin):
    assert admin.post("/api/auth/logout").status_code == 200
    assert admin.get("/api/admin/monitors").status_code == 401


def test_settings(admin):
    res = admin.put("/api/admin/settings", json={"title": "Acme Status", "description": "All Acme services"})
    assert res.status_code == 200
    site = admin.get("/api/status").json()["site"]
    assert site == {"title": "Acme Status", "description": "All Acme services"}
    assert admin.put("/api/admin/settings", json={"title": ""}).status_code == 422
