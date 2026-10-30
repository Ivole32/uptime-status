"""Unauthenticated endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from ..config import Settings, get_settings
from ..db import get_db
from ..models import LegalPage
from ..schemas import LEGAL_DEFAULT_TITLES, LegalKind, iso_utc
from ..stats import get_site_settings, legal_links, status_cache

router = APIRouter()


@router.get("/api/status")
def public_status(
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    response.headers["Cache-Control"] = f"public, max-age={settings.public_cache_seconds}"
    return status_cache.get(db, settings)


@router.get("/api/legal/{kind}")
def legal_page(
    kind: LegalKind,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    page = db.get(LegalPage, kind.value)
    if page is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Page not found")
    response.headers["Cache-Control"] = f"public, max-age={settings.public_cache_seconds}"
    return {
        "kind": kind.value,
        "title": page.title or LEGAL_DEFAULT_TITLES[kind],
        "content": page.content,
        "updated_at": iso_utc(page.updated_at),
        "site": {"title": get_site_settings(db)["title"]},
        "legal": legal_links(db),
    }


@router.get("/healthz", include_in_schema=False)
def healthz() -> dict:
    return {"ok": True}
