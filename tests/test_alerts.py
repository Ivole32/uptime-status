import json
import threading
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app import alerts
from app.alerts import AlertConfig, PushgateClient, PushgateError, alert_status, run_alerts, save_alert_config
from app.checker import ProbeResult
from app.config import _pushgate_url, get_settings
from app.db import SessionLocal, utcnow
from app.models import Incident, Monitor
from app.scheduler import record_result

KEY = "pgk_0123456789abcdef_" + "A" * 43
MONITOR = {"name": "Website", "url": "example.com", "interval_seconds": 60, "timeout_seconds": 10}


class FakeClient:
    def __init__(self, fail: PushgateError | None = None, status: str = "delivered") -> None:
        self.sent: list[dict] = []
        self.fail = fail
        self.status = status

    def send(self, title, message, priority="normal", tag=None):
        if self.fail:
            raise self.fail
        self.sent.append({"title": title, "message": message, "priority": priority, "tag": tag})
        return {"status": self.status}


@pytest.fixture(autouse=True)
def _reset_status():
    alert_status.reset()
    yield
    alert_status.reset()


def _configure(**overrides) -> None:
    with SessionLocal() as db:
        save_alert_config(db, AlertConfig(**{"enabled": True, "after_minutes": 5, **overrides}))
        db.commit()


def _monitor(**fields) -> int:
    with SessionLocal() as db:
        m = Monitor(**{"name": "Website", "url": "https://example.com/", **fields})
        db.add(m)
        db.commit()
        return m.id


def _down(mid: int, error: str = "HTTP 503") -> None:
    record_result(mid, ProbeResult(False, None, 503, error))


def _up(mid: int) -> None:
    record_result(mid, ProbeResult(True, 50, 200, None))


def _incident(mid: int) -> Incident:
    with SessionLocal() as db:
        return db.query(Incident).filter_by(monitor_id=mid).order_by(Incident.id.desc()).first()


def _run(client, minutes: float = 0) -> int:
    return run_alerts(get_settings(), client=client, now=utcnow() + timedelta(minutes=minutes))


def test_outage_alerted_only_after_delay_and_once():
    _configure(after_minutes=5)
    mid = _monitor()
    _down(mid)
    client = FakeClient()
    assert _run(client, minutes=4) == 0
    assert _run(client, minutes=5.1) == 1
    alert = client.sent[0]
    assert alert["title"] == "Website is down" and alert["priority"] == "high"
    assert alert["tag"] == f"uptime-{mid}"
    assert "Down for 5 min" in alert["message"] and "HTTP 503" in alert["message"]
    assert _incident(mid).alert_sent_at is not None
    assert _run(client, minutes=10) == 0  # not repeated


def test_short_outage_is_never_alerted():
    _configure(after_minutes=5)
    mid = _monitor()
    _down(mid)
    _up(mid)
    client = FakeClient()
    assert _run(client, minutes=60) == 0
    assert client.sent == []


def test_disabled_globally_sends_nothing():
    _configure(enabled=False, after_minutes=0)
    mid = _monitor()
    _down(mid)
    client = FakeClient()
    assert _run(client, minutes=60) == 0


def test_per_monitor_delay_and_opt_out():
    _configure(after_minutes=30)
    fast = _monitor(name="Fast", alert_after_minutes=1)
    muted = _monitor(name="Muted", alerts_enabled=False)
    paused = _monitor(name="Paused")
    for mid in (fast, muted, paused):
        _down(mid)
    with SessionLocal() as db:
        db.get(Monitor, paused).enabled = False
        db.commit()
    client = FakeClient()
    _run(client, minutes=2)
    assert [a["title"] for a in client.sent] == ["Fast is down"]
    _run(client, minutes=31)
    assert [a["title"] for a in client.sent] == ["Fast is down"]


def test_zero_delay_alerts_immediately():
    _configure(after_minutes=0)
    mid = _monitor()
    _down(mid)
    client = FakeClient()
    assert _run(client) == 1


def test_recovery_follows_an_alerted_outage():
    _configure(after_minutes=0, priority="high")
    mid = _monitor()
    _down(mid)
    client = FakeClient()
    _run(client)
    _up(mid)
    assert _run(client) == 1
    recovery = client.sent[-1]
    assert recovery["title"] == "Website is back up" and recovery["priority"] == "normal"
    assert recovery["tag"] == f"uptime-{mid}"
    assert _incident(mid).recovery_sent_at is not None
    assert _run(client) == 0


def test_recovery_can_be_turned_off():
    _configure(after_minutes=0, on_recovery=False)
    mid = _monitor()
    _down(mid)
    client = FakeClient()
    _run(client)
    _up(mid)
    assert _run(client) == 0


def test_stale_recovery_is_not_announced():
    _configure(after_minutes=0)
    mid = _monitor()
    _down(mid)
    client = FakeClient()
    _run(client)
    _up(mid)
    assert _run(client, minutes=60 * 25) == 0


def test_degraded_alerts_are_opt_in():
    _configure(after_minutes=0)
    mid = _monitor()
    with SessionLocal() as db:
        db.add(Incident(monitor_id=mid, started_at=utcnow(), kind="degraded", error="Elevated latency: 900 ms"))
        db.commit()
    client = FakeClient()
    assert _run(client) == 0
    _configure(after_minutes=0, on_degraded=True)
    assert _run(client) == 1
    assert client.sent[0]["title"] == "Website is slow"


def test_many_outages_are_grouped():
    _configure(after_minutes=0)
    ids = [_monitor(name=f"Service {i}") for i in range(5)]
    for mid in ids:
        _down(mid)
    client = FakeClient()
    assert _run(client) == 1
    assert client.sent[0]["title"] == "5 services have problems"
    assert client.sent[0]["message"].count("\n") == 4
    with SessionLocal() as db:
        assert all(i.alert_sent_at for i in db.query(Incident))


def test_failure_backs_off_and_keeps_alert_pending():
    _configure(after_minutes=0)
    mid = _monitor()
    _down(mid)
    failing = FakeClient(fail=PushgateError("Pushgate is unreachable: refused"))
    assert _run(failing) == 0
    assert alert_status.last_error.startswith("Pushgate is unreachable")
    assert alert_status.retry_at is not None
    assert _incident(mid).alert_sent_at is None
    ok = FakeClient()
    assert _run(ok) == 0  # still pausing
    assert _run(ok, minutes=1) == 1
    assert alert_status.last_error is None and alert_status.failures == 0


def test_text_is_cleaned_for_pushgate():
    assert alerts._line("a‮b\nc\td", 100) == "a b c d"
    assert len(alerts._line("x" * 300, 150)) == 150
    assert alerts._text("one\n​two", 100) == "one\ntwo"


def test_pushgate_url_must_be_https(monkeypatch):
    monkeypatch.setenv("UPTIME_PUSHGATE_URL", "https://notify.example.com/api/v1/notifications/")
    assert _pushgate_url("PUSHGATE_URL") == "https://notify.example.com"
    monkeypatch.setenv("UPTIME_PUSHGATE_URL", "http://notify.example.com")
    with pytest.raises(ValueError):
        _pushgate_url("PUSHGATE_URL")


# ---------- The HTTP client against a local fake Pushgate ----------


class _Pushgate(BaseHTTPRequestHandler):
    requests: list[dict] = []
    reply: tuple[int, dict, dict] = (200, {"status": "delivered"}, {})

    def do_POST(self):  # noqa: N802
        length = int(self.headers["Content-Length"])
        _Pushgate.requests.append(
            {"path": self.path, "auth": self.headers["Authorization"], "body": json.loads(self.rfile.read(length))}
        )
        code, body, headers = _Pushgate.reply
        self.send_response(code)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    def log_message(self, *args):
        pass


@pytest.fixture
def pushgate():
    _Pushgate.requests = []
    _Pushgate.reply = (200, {"status": "delivered"}, {})
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Pushgate)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def test_client_sends_notification(pushgate):
    client = PushgateClient(pushgate, KEY)
    assert client.send("Website is down", "Down for 5 min", "high", "uptime-1") == {"status": "delivered"}
    req = _Pushgate.requests[0]
    assert req["path"] == "/api/v1/notifications" and req["auth"] == "Bearer " + KEY
    assert req["body"] == {"title": "Website is down", "message": "Down for 5 min", "priority": "high", "tag": "uptime-1"}


def test_client_explains_errors(pushgate):
    client = PushgateClient(pushgate, KEY)
    _Pushgate.reply = (403, {"error": {"code": "insufficient_scope"}}, {})
    with pytest.raises(PushgateError, match="notifications:send:high"):
        client.send("t", "m", "high")
    _Pushgate.reply = (429, {"error": {"code": "rate_limited"}}, {"Retry-After": "42"})
    with pytest.raises(PushgateError) as exc:
        client.send("t", "m")
    assert exc.value.retry_after == 42


def test_client_does_not_follow_redirects(pushgate):
    _Pushgate.reply = (307, {}, {"Location": "https://elsewhere.example/"})
    with pytest.raises(PushgateError, match="redirected"):
        PushgateClient(pushgate, KEY).send("t", "m")
    assert len(_Pushgate.requests) == 1


def test_client_key_file(tmp_path):
    key_file = tmp_path / "pushgate.key"
    client = PushgateClient("https://notify.example.com", key_file=key_file)
    assert "UPTIME_PUSHGATE_KEY" in client.problem()
    key_file.write_text("not-a-key\n")
    assert "wrong format" in client.problem()
    key_file.write_text(KEY + "\n")
    assert client.problem() is None
    assert PushgateClient(None, KEY).problem() == "UPTIME_PUSHGATE_URL is not set"


# ---------- Admin API ----------


def test_admin_alert_settings(admin):
    res = admin.get("/api/admin/alerts")
    assert res.status_code == 200
    body = res.json()
    assert body["enabled"] is False and body["after_minutes"] == 5
    assert body["pushgate"]["problem"] == "UPTIME_PUSHGATE_URL is not set"

    res = admin.put("/api/admin/alerts", json={"enabled": True, "after_minutes": 15, "priority": "normal"})
    assert res.status_code == 200, res.text
    assert res.json()["after_minutes"] == 15 and res.json()["priority"] == "normal"
    assert admin.get("/api/admin/alerts").json()["enabled"] is True

    assert admin.put("/api/admin/alerts", json={"enabled": True, "after_minutes": 5000}).status_code == 422
    assert admin.put("/api/admin/alerts", json={"enabled": True, "after_minutes": 5, "priority": "urgent"}).status_code == 422

    res = admin.post("/api/admin/alerts/test", json={})
    assert res.status_code == 502 and "UPTIME_PUSHGATE_URL" in res.json()["detail"]


def test_admin_alerts_require_login(client):
    assert client.get("/api/admin/alerts").status_code == 401


def test_monitor_alert_fields(admin):
    created = admin.post("/api/admin/monitors", json=MONITOR).json()
    assert created["alerts_enabled"] is True and created["alert_after_minutes"] is None
    res = admin.put(
        f"/api/admin/monitors/{created['id']}", json={**MONITOR, "alerts_enabled": False, "alert_after_minutes": 2}
    )
    assert res.status_code == 200
    assert res.json()["alerts_enabled"] is False and res.json()["alert_after_minutes"] == 2
    bad = admin.post("/api/admin/monitors", json={**MONITOR, "alert_after_minutes": -1})
    assert bad.status_code == 422
