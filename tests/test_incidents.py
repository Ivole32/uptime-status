from datetime import timedelta

from fastapi.testclient import TestClient

from app.checker import ProbeResult
from app.config import get_settings
from app.db import SessionLocal, utcnow
from app.main import app
from app.models import Incident, IncidentUpdate, Monitor
from app.scheduler import INCIDENT_RETENTION, record_result, run_maintenance

MONITOR = {"name": "Website", "url": "example.com", "interval_seconds": 60, "timeout_seconds": 10}


def _incident(admin, **monitor) -> int:
    mid = admin.post("/api/admin/monitors", json={**MONITOR, **monitor}).json()["id"]
    record_result(mid, ProbeResult(False, None, None, "Connection refused"))
    with SessionLocal() as db:
        return db.query(Incident).filter_by(monitor_id=mid).one().id


def test_incident_updates_lifecycle(admin):
    iid = _incident(admin)
    res = admin.post(f"/api/admin/incidents/{iid}/updates", json={"status": "investigating", "message": "Looking into it."})
    assert res.status_code == 201, res.text
    first = res.json()["updates"][0]
    assert first["status"] == "investigating" and first["created_at"].endswith("Z")
    res = admin.post(f"/api/admin/incidents/{iid}/updates", json={"status": "identified", "message": "Disk **full**."})
    assert [u["status"] for u in res.json()["updates"]] == ["identified", "investigating"]

    page = admin.get(f"/api/incidents/{iid}")
    assert page.status_code == 200
    incident = page.json()["incident"]
    assert [u["message"] for u in incident["updates"]] == ["Disk **full**.", "Looking into it."]
    assert incident["error"] == "Service unreachable"  # coarse, like the status page
    assert "monitor_public" not in incident
    html = admin.get(f"/incidents/{iid}")
    assert html.status_code == 200 and "text/html" in html.headers["content-type"]

    active = admin.get("/api/status").json()["incidents"]["active"][0]
    assert active["latest_update"]["status"] == "identified" and active["has_postmortem"] is False

    edited = admin.put(
        f"/api/admin/incidents/{iid}/updates/{first['id']}", json={"status": "investigating", "message": "Still looking."}
    )
    assert edited.status_code == 200 and edited.json()["updates"][1]["message"] == "Still looking."
    second = edited.json()["updates"][0]["id"]
    assert admin.delete(f"/api/admin/incidents/{iid}/updates/{second}").status_code == 204
    assert admin.delete(f"/api/admin/incidents/{iid}/updates/{second}").status_code == 404

    listed = admin.get("/api/admin/incidents").json()[0]
    assert listed["update_count"] == 1 and listed["latest_status"] == "investigating"
    assert listed["error"] == "Connection refused"  # the admin still sees the exact reason
    assert admin.get("/api/status").json()["incidents"]["active"][0]["latest_update"]["message"] == "Still looking."

    # Resolution still follows the checks; the updates stay with the resolved incident.
    record_result(listed["monitor_id"], ProbeResult(True, 50, 200, None))
    past = admin.get("/api/status").json()["incidents"]["past"][0]
    assert past["id"] == iid and past["latest_update"]["status"] == "investigating"


def test_incident_title_and_postmortem(admin):
    iid = _incident(admin)
    res = admin.put(f"/api/admin/incidents/{iid}", json={"title": "  Database\n outage ", "postmortem": "# Cause\nA full disk."})
    assert res.status_code == 200, res.text
    saved = res.json()
    assert saved["title"] == "Database outage" and saved["postmortem_at"].endswith("Z")

    public = admin.get(f"/api/incidents/{iid}").json()["incident"]
    assert public["title"] == "Database outage" and public["postmortem"] == "# Cause\nA full disk."
    assert admin.get("/api/status").json()["incidents"]["active"][0]["has_postmortem"] is True

    # Changing only the title keeps the post-mortem date.
    with SessionLocal() as db:
        db.get(Incident, iid).postmortem_at = utcnow() - timedelta(days=2)
        db.commit()
    renamed = admin.put(f"/api/admin/incidents/{iid}", json={"title": "Outage", "postmortem": "# Cause\nA full disk."})
    assert renamed.json()["postmortem_at"] < saved["postmortem_at"]

    cleared = admin.put(f"/api/admin/incidents/{iid}", json={"title": " ", "postmortem": ""}).json()
    assert cleared["title"] is None and cleared["postmortem"] is None and cleared["postmortem_at"] is None
    # Both fields are required, so leaving one out cannot clear it by accident.
    assert admin.put(f"/api/admin/incidents/{iid}", json={"title": "Outage"}).status_code == 422


def test_incident_input_validation(admin):
    iid = _incident(admin)
    other = _incident(admin, name="Other")
    url = f"/api/admin/incidents/{iid}/updates"
    for body in (
        {"status": "fixed", "message": "x"},
        {"status": "update", "message": "  \n "},
        {"status": "update", "message": "x" * 5001},
        {"status": "update"},
        {"status": "update", "message": "x", "extra": 1},
    ):
        assert admin.post(url, json=body).status_code == 422, body
    assert admin.post("/api/admin/incidents/999/updates", json={"status": "update", "message": "x"}).status_code == 404
    uid = admin.post(f"/api/admin/incidents/{other}/updates", json={"status": "update", "message": "x"}).json()["updates"][0]["id"]
    # An update is only reachable through its own incident.
    assert admin.put(f"{url}/{uid}", json={"status": "update", "message": "y"}).status_code == 404
    assert admin.delete(f"{url}/{uid}").status_code == 404
    assert admin.put(f"/api/admin/incidents/{iid}", json={"title": "x" * 121, "postmortem": None}).status_code == 422
    assert admin.put(f"/api/admin/incidents/{iid}", json={"title": None, "postmortem": "x" * 20_001}).status_code == 422
    assert admin.put(f"/api/admin/incidents/{iid}", json={"title": None, "postmortem": "x" * 20_000}).status_code == 200


def test_incident_text_is_stored_not_interpreted(admin):
    iid = _incident(admin)
    message = "Fixed\x00\x07 <script>alert(1)</script> [x](javascript:alert(1))"
    res = admin.post(f"/api/admin/incidents/{iid}/updates", json={"status": "resolved", "message": message})
    assert res.json()["updates"][0]["message"] == "Fixed <script>alert(1)</script> [x](javascript:alert(1))"
    assert "<script>" not in admin.get(f"/incidents/{iid}").text


def test_incident_writes_require_login_and_csrf(client, admin):
    iid = _incident(admin)
    update = {"status": "update", "message": "Hi"}
    with TestClient(app) as anonymous:
        assert anonymous.get(f"/api/admin/incidents/{iid}").status_code == 401
        assert anonymous.post(f"/api/admin/incidents/{iid}/updates", json=update).status_code == 401
        assert anonymous.put(f"/api/admin/incidents/{iid}", json={"title": "x", "postmortem": None}).status_code == 401
    token = admin.headers.pop("X-CSRF-Token")
    assert admin.post(f"/api/admin/incidents/{iid}/updates", json=update).status_code == 403
    res = admin.post(
        f"/api/admin/incidents/{iid}/updates", json=update, headers={"X-CSRF-Token": token, "Origin": "https://evil.example"}
    )
    assert res.status_code == 403
    assert admin.get(f"/api/incidents/{iid}").json()["incident"]["updates"] == []


def test_incident_page_only_for_public_monitors(admin):
    hidden = _incident(admin, name="Internal", is_public=False)
    paused = _incident(admin, name="Paused")
    with SessionLocal() as db:
        db.get(Monitor, db.get(Incident, paused).monitor_id).enabled = False
        db.commit()
    admin.post(f"/api/admin/incidents/{hidden}/updates", json={"status": "update", "message": "Secret"})
    with TestClient(app) as anonymous:
        for iid in (hidden, paused, 999):
            assert anonymous.get(f"/api/incidents/{iid}").status_code == 404, iid
            assert anonymous.get(f"/incidents/{iid}").status_code == 404, iid
        for path in ("/incidents/abc", "/incidents/0", "/incidents/-1", "/incidents/99999999999", "/incidents/1e3"):
            assert anonymous.get(path).status_code == 404, path
        assert anonymous.get("/api/incidents/0").status_code == 422
    # The admin can still open it, and is told visitors cannot.
    detail = admin.get(f"/api/admin/incidents/{hidden}").json()
    assert detail["monitor_public"] is False and detail["updates"][0]["message"] == "Secret"


def test_written_incidents_survive_retention(admin):
    plain, updated, titled, postmortem = (_incident(admin, name=f"M{i}") for i in range(4))
    admin.post(f"/api/admin/incidents/{updated}/updates", json={"status": "resolved", "message": "Fixed."})
    admin.put(f"/api/admin/incidents/{titled}", json={"title": "Outage", "postmortem": None})
    admin.put(f"/api/admin/incidents/{postmortem}", json={"title": None, "postmortem": "What happened"})
    old = utcnow() - INCIDENT_RETENTION - timedelta(days=1)
    with SessionLocal() as db:
        for inc in db.query(Incident):
            inc.started_at = inc.resolved_at = old
        db.commit()
    run_maintenance(get_settings())
    with SessionLocal() as db:
        assert {i.id for i in db.query(Incident)} == {updated, titled, postmortem}
    assert admin.get(f"/api/incidents/{updated}").status_code == 200


def test_deleting_incident_removes_updates(admin):
    iid = _incident(admin)
    admin.post(f"/api/admin/incidents/{iid}/updates", json={"status": "update", "message": "x"})
    assert admin.delete(f"/api/admin/incidents/{iid}").status_code == 204
    with SessionLocal() as db:
        assert db.query(IncidentUpdate).count() == 0
    assert admin.get(f"/api/incidents/{iid}").status_code == 404
