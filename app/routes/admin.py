"""Authenticated admin API. Every route requires a session (and CSRF token for writes)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response, status
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..auth import require_admin
from ..config import Settings, get_settings
from ..db import get_db, utcnow
from ..models import AdminSession, Check, Incident, IncidentUpdate, LegalPage, Monitor, SiteSetting
from ..schemas import (
    CheckOut,
    IncidentDetailOut,
    IncidentIn,
    IncidentOut,
    IncidentUpdateIn,
    LegalKind,
    LegalPageIn,
    MonitorIn,
    MonitorOut,
    SiteSettingsIn,
    iso_utc,
)
from ..stats import get_legal_pages, get_site_settings, status_cache

router = APIRouter(prefix="/api/admin", dependencies=[Depends(require_admin)])

# Bounded so oversized IDs are a 422, not an integer overflow in the database driver.
ObjectId = Annotated[int, Path(ge=1, le=2**31 - 1)]


def _no_store(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"


def _get_monitor(db: Session, monitor_id: int) -> Monitor:
    monitor = db.get(Monitor, monitor_id)
    if monitor is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Monitor not found")
    return monitor


def _changed(request: Request) -> None:
    status_cache.invalidate()
    scheduler = getattr(request.app.state, "scheduler", None)
    if scheduler is not None:
        scheduler.wake()


@router.get("/monitors", response_model=list[MonitorOut])
def list_monitors(response: Response, db: Session = Depends(get_db)) -> list[Monitor]:
    _no_store(response)
    return list(db.scalars(select(Monitor).order_by(Monitor.sort_order, Monitor.name, Monitor.id)))


@router.post("/monitors", response_model=MonitorOut, status_code=status.HTTP_201_CREATED)
def create_monitor(
    body: MonitorIn,
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Monitor:
    if db.scalar(select(func.count()).select_from(Monitor)) >= settings.max_monitors:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Monitor limit ({settings.max_monitors}) reached")
    monitor = Monitor(**body.model_dump())
    db.add(monitor)
    db.commit()
    db.refresh(monitor)
    _changed(request)
    return monitor


@router.put("/monitors/{monitor_id}", response_model=MonitorOut)
def update_monitor(
    monitor_id: ObjectId, body: MonitorIn, request: Request, db: Session = Depends(get_db)
) -> Monitor:
    monitor = _get_monitor(db, monitor_id)
    data = body.model_dump()
    if data["url"] != monitor.url:
        monitor.status = "pending"
        monitor.last_checked_at = None
    for key, value in data.items():
        setattr(monitor, key, value)
    db.commit()
    db.refresh(monitor)
    _changed(request)
    return monitor


@router.delete("/monitors/{monitor_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_monitor(monitor_id: ObjectId, request: Request, db: Session = Depends(get_db)) -> Response:
    db.delete(_get_monitor(db, monitor_id))
    db.commit()
    _changed(request)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/monitors/{monitor_id}/check", status_code=status.HTTP_202_ACCEPTED)
def check_now(monitor_id: ObjectId, request: Request, db: Session = Depends(get_db)) -> dict:
    monitor = _get_monitor(db, monitor_id)
    if not monitor.enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "Monitor is paused")
    monitor.last_checked_at = None
    db.commit()
    _changed(request)
    return {"queued": True}


@router.get("/monitors/{monitor_id}/checks", response_model=list[CheckOut])
def recent_checks(
    monitor_id: ObjectId,
    response: Response,
    limit: int = Query(default=50, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[Check]:
    _no_store(response)
    _get_monitor(db, monitor_id)
    return list(
        db.scalars(
            select(Check)
            .where(Check.monitor_id == monitor_id)
            .order_by(Check.checked_at.desc())
            .limit(limit)
        )
    )


@router.get("/incidents", response_model=list[IncidentOut])
def list_incidents(
    response: Response,
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
) -> list[dict]:
    _no_store(response)
    of_incident = IncidentUpdate.incident_id == Incident.id
    update_count = select(func.count()).where(of_incident).correlate(Incident).scalar_subquery()
    latest_status = (
        select(IncidentUpdate.status)
        .where(of_incident)
        .order_by(IncidentUpdate.created_at.desc(), IncidentUpdate.id.desc())
        .limit(1)
        .correlate(Incident)
        .scalar_subquery()
    )
    rows = db.execute(
        select(Incident, Monitor.name, update_count, latest_status)
        .join(Monitor, Monitor.id == Incident.monitor_id)
        .order_by(Incident.started_at.desc())
        .limit(limit)
    )
    return [
        {
            "id": inc.id,
            "monitor_id": inc.monitor_id,
            "monitor_name": name,
            "started_at": inc.started_at,
            "resolved_at": inc.resolved_at,
            "kind": inc.kind,
            "error": inc.error,
            "title": inc.title,
            "update_count": count,
            "latest_status": latest,
            "has_postmortem": inc.postmortem is not None,
        }
        for inc, name, count, latest in rows
    ]


def _get_incident(db: Session, incident_id: int) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
    return incident


def _get_update(db: Session, incident_id: int, update_id: int) -> IncidentUpdate:
    update = db.get(IncidentUpdate, update_id)
    if update is None or update.incident_id != incident_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Update not found")
    return update


def _incident_detail(db: Session, incident: Incident) -> dict:
    monitor = db.get(Monitor, incident.monitor_id)
    updates = db.scalars(
        select(IncidentUpdate)
        .where(IncidentUpdate.incident_id == incident.id)
        .order_by(IncidentUpdate.created_at.desc(), IncidentUpdate.id.desc())
    )
    return {
        "id": incident.id,
        "monitor_id": incident.monitor_id,
        "monitor_name": monitor.name,
        "monitor_public": monitor.enabled and monitor.is_public,
        "started_at": incident.started_at,
        "resolved_at": incident.resolved_at,
        "kind": incident.kind,
        "error": incident.error,
        "title": incident.title,
        "postmortem": incident.postmortem,
        "postmortem_at": incident.postmortem_at,
        "updates": list(updates),
    }


@router.get("/incidents/{incident_id}", response_model=IncidentDetailOut)
def read_incident(incident_id: ObjectId, response: Response, db: Session = Depends(get_db)) -> dict:
    _no_store(response)
    return _incident_detail(db, _get_incident(db, incident_id))


@router.put("/incidents/{incident_id}", response_model=IncidentDetailOut)
def write_incident(incident_id: ObjectId, body: IncidentIn, db: Session = Depends(get_db)) -> dict:
    incident = _get_incident(db, incident_id)
    incident.title = body.title
    if body.postmortem != incident.postmortem:
        incident.postmortem = body.postmortem
        incident.postmortem_at = utcnow() if body.postmortem else None
    db.commit()
    status_cache.invalidate()
    return _incident_detail(db, incident)


@router.delete("/incidents/{incident_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_incident(incident_id: ObjectId, db: Session = Depends(get_db)) -> Response:
    db.delete(_get_incident(db, incident_id))
    db.commit()
    status_cache.invalidate()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/incidents/{incident_id}/updates",
    response_model=IncidentDetailOut,
    status_code=status.HTTP_201_CREATED,
)
def post_incident_update(incident_id: ObjectId, body: IncidentUpdateIn, db: Session = Depends(get_db)) -> dict:
    incident = _get_incident(db, incident_id)
    db.add(IncidentUpdate(incident_id=incident.id, status=body.status.value, message=body.message))
    db.commit()
    status_cache.invalidate()
    return _incident_detail(db, incident)


@router.put("/incidents/{incident_id}/updates/{update_id}", response_model=IncidentDetailOut)
def edit_incident_update(
    incident_id: ObjectId, update_id: ObjectId, body: IncidentUpdateIn, db: Session = Depends(get_db)
) -> dict:
    update = _get_update(db, incident_id, update_id)
    update.status, update.message = body.status.value, body.message
    db.commit()
    status_cache.invalidate()
    return _incident_detail(db, _get_incident(db, incident_id))


@router.delete("/incidents/{incident_id}/updates/{update_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_incident_update(incident_id: ObjectId, update_id: ObjectId, db: Session = Depends(get_db)) -> Response:
    db.delete(_get_update(db, incident_id, update_id))
    db.commit()
    status_cache.invalidate()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/settings")
def read_settings(response: Response, db: Session = Depends(get_db)) -> dict:
    _no_store(response)
    return get_site_settings(db)


@router.put("/settings")
def write_settings(body: SiteSettingsIn, db: Session = Depends(get_db)) -> dict:
    for key, value in body.model_dump().items():
        row = db.get(SiteSetting, key)
        if row is None:
            db.add(SiteSetting(key=key, value=value or ""))
        else:
            row.value = value or ""
    db.commit()
    status_cache.invalidate()
    return get_site_settings(db)


def _legal_out(kind: LegalKind, page: LegalPage | None) -> dict:
    return {
        "kind": kind.value,
        "title": page.title if page else None,
        "content": page.content if page else None,
        "updated_at": iso_utc(page.updated_at) if page else None,
    }


@router.get("/legal")
def read_legal(response: Response, db: Session = Depends(get_db)) -> list[dict]:
    _no_store(response)
    pages = get_legal_pages(db)
    return [_legal_out(kind, pages.get(kind)) for kind in LegalKind]


async def legal_body(request: Request, _session: AdminSession = Depends(require_admin)) -> LegalPageIn:
    """Parse the body only after the session and CSRF token are checked.

    A declared body parameter would be read before any dependency runs, letting anonymous
    clients make the server buffer bodies up to the larger limit of this route.
    """
    try:
        return LegalPageIn.model_validate_json(await request.body())
    except ValidationError as exc:
        raise RequestValidationError([{**e, "loc": ("body", *e["loc"])} for e in exc.errors()]) from None


@router.put("/legal/{kind}")
def write_legal(
    kind: LegalKind, body: LegalPageIn = Depends(legal_body), db: Session = Depends(get_db)
) -> dict:
    page = db.get(LegalPage, kind.value)
    if body.content is None:
        if page is not None:
            db.delete(page)
            page = None
    elif page is None:
        page = LegalPage(kind=kind.value, title=body.title, content=body.content)
        db.add(page)
    elif (page.title, page.content) != (body.title, body.content):
        page.title, page.content, page.updated_at = body.title, body.content, utcnow()
    db.commit()
    status_cache.invalidate()
    return _legal_out(kind, page)
