"""Unauthenticated endpoints."""

from __future__ import annotations

from typing import Annotated
from xml.sax.saxutils import escape

from fastapi import APIRouter, Depends, HTTPException, Path, Response, status
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from ..config import Settings, get_settings
from ..db import get_db
from ..models import LegalPage
from ..schemas import LEGAL_DEFAULT_TITLES, LegalKind, iso_utc
from ..stats import (
    get_legal_pages,
    get_public_incident,
    get_site_settings,
    legal_links,
    public_incident_pages,
    status_cache,
)

router = APIRouter()
# The protocol's limit per sitemap file.
SITEMAP_MAX_URLS = 50_000


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


@router.get("/api/incidents/{incident_id}")
def incident(
    incident_id: Annotated[int, Path(ge=1, le=2**31 - 1)],
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    found = get_public_incident(db, incident_id)
    if found is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
    response.headers["Cache-Control"] = f"public, max-age={settings.public_cache_seconds}"
    return {
        "incident": found,
        "refresh_seconds": settings.public_refresh_seconds,
        "site": {"title": get_site_settings(db)["title"]},
        "legal": legal_links(db),
    }


@router.get("/robots.txt", include_in_schema=False)
def robots_txt(settings: Settings = Depends(get_settings)) -> PlainTextResponse:
    # /api/status and /api/incidents stay crawlable: the pages are rendered from them.
    lines = ["User-agent: *", "Disallow: /admin", "Disallow: /api/admin/", "Disallow: /api/auth/"]
    if settings.site_url:
        lines += ["", f"Sitemap: {settings.site_url}/sitemap.xml"]
    return PlainTextResponse("\n".join(lines) + "\n", headers={"Cache-Control": "public, max-age=3600"})


@router.get("/sitemap.xml", include_in_schema=False)
def sitemap_xml(db: Session = Depends(get_db), settings: Settings = Depends(get_settings)) -> Response:
    # A sitemap needs absolute URLs, and the Host header is client-supplied.
    if not settings.site_url:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")
    pages: list[tuple[str, str | None]] = [("/", None)]
    pages += [(f"/{kind.value}", iso_utc(page.updated_at)) for kind, page in get_legal_pages(db).items()]
    incidents = public_incident_pages(db, SITEMAP_MAX_URLS - len(pages))
    pages += [(f"/incidents/{iid}", iso_utc(changed)) for iid, changed in incidents]

    entries = []
    for path, lastmod in pages:
        entry = f"<url><loc>{escape(settings.site_url + path)}</loc>"
        if lastmod:
            entry += f"<lastmod>{lastmod}</lastmod>"
        entries.append(entry + "</url>")
    body = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + "\n".join(entries)
        + "\n</urlset>\n"
    )
    return Response(body, media_type="application/xml", headers={"Cache-Control": "public, max-age=300"})


@router.get("/healthz", include_in_schema=False)
def healthz() -> dict:
    return {"ok": True}
