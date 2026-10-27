"""Login, logout and session introspection."""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.orm import Session

from ..auth import (
    LoginBusy,
    check_login,
    clear_session_cookie,
    client_ip,
    create_session,
    login_limiter,
    optional_session,
    rate_limit_key,
    require_admin,
)
from ..config import Settings, get_settings
from ..db import get_db
from ..models import AdminSession
from ..schemas import LoginIn

log = logging.getLogger("uptime.auth")
router = APIRouter(prefix="/api/auth")


@router.post("/login")
async def login(
    body: LoginIn,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    ip = client_ip(request)
    key = rate_limit_key(ip)
    token, wait = login_limiter.reserve(key)
    if token is None:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Too many failed login attempts. Try again later.",
            headers={"Retry-After": str(wait)},
        )
    try:
        creds = await run_in_threadpool(check_login, settings, body.username, body.password)
    except LoginBusy:
        login_limiter.release(key, token)
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "Server busy. Try again in a moment.",
            headers={"Retry-After": "1"},
        ) from None
    if creds is None:
        log.warning("Failed admin login from %s", ip)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")
    login_limiter.record_success(key)
    log.info("Admin login from %s", ip)
    csrf = await run_in_threadpool(create_session, db, settings, creds, response)
    response.headers["Cache-Control"] = "no-store"
    return {"authenticated": True, "csrf_token": csrf}


@router.post("/logout")
def logout(
    response: Response,
    session: AdminSession = Depends(require_admin),
    db: Session = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> dict:
    db.delete(session)
    db.commit()
    clear_session_cookie(settings, response)
    return {"authenticated": False}


@router.get("/me")
def me(response: Response, session: AdminSession | None = Depends(optional_session)) -> dict:
    response.headers["Cache-Control"] = "no-store"
    if session is None:
        return {"authenticated": False}
    return {"authenticated": True, "csrf_token": session.csrf_token}
