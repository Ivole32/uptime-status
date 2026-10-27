"""Unauthenticated endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from ..config import Settings, get_settings
from ..db import get_db
from ..stats import status_cache

router = APIRouter()


@router.get("/api/status")
def public_status(
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    response.headers["Cache-Control"] = f"public, max-age={settings.public_cache_seconds}"
    return status_cache.get(db, settings)


@router.get("/healthz", include_in_schema=False)
def healthz() -> dict:
    return {"ok": True}
