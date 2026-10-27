"""FastAPI application factory."""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__
from .config import get_settings
from .routes import admin, auth, public
from .scheduler import Scheduler
from .security import BodySizeLimitMiddleware, OriginCheckMiddleware, SecurityHeadersMiddleware

log = logging.getLogger("uptime")
STATIC_DIR = Path(__file__).parent / "static"
MAX_BODY_BYTES = 64 * 1024


class CachedStaticFiles(StaticFiles):
    async def get_response(self, path, scope):  # type: ignore[override]
        response = await super().get_response(path, scope)
        response.headers.setdefault("Cache-Control", "public, max-age=300")
        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    scheduler = Scheduler(settings) if settings.scheduler_enabled else None
    app.state.scheduler = scheduler
    task = asyncio.create_task(scheduler.run()) if scheduler else None
    try:
        yield
    finally:
        if scheduler and task:
            await scheduler.stop()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


def create_app() -> FastAPI:
    settings = get_settings()
    docs = settings.enable_api_docs
    app = FastAPI(
        title="Uptime Status",
        version=__version__,
        lifespan=lifespan,
        docs_url="/api/docs" if docs else None,
        redoc_url=None,
        openapi_url="/api/openapi.json" if docs else None,
        # Slash redirects would build Location from the client-supplied Host header.
        redirect_slashes=False,
    )
    if not settings.allowed_hosts:
        log.warning("UPTIME_ALLOWED_HOSTS is not set; requests for any Host header are accepted")

    @app.exception_handler(StarletteHTTPException)
    async def http_error(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, exc: RequestValidationError) -> JSONResponse:
        # Return field + message only; never echo the submitted input back.
        errors = [
            {"field": ".".join(str(p) for p in err.get("loc", ())[1:]), "message": err.get("msg", "")}
            for err in exc.errors()
        ]
        return JSONResponse({"detail": "Invalid input", "errors": errors}, status_code=422)

    @app.exception_handler(Exception)
    async def unhandled_error(_request: Request, exc: Exception) -> JSONResponse:
        log.exception("Unhandled error", exc_info=exc)
        return JSONResponse({"detail": "Internal server error"}, status_code=500)

    app.include_router(public.router)
    app.include_router(auth.router)
    app.include_router(admin.router)

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html", headers={"Cache-Control": "no-cache"})

    @app.get("/admin", include_in_schema=False)
    def admin_page() -> FileResponse:
        return FileResponse(
            STATIC_DIR / "admin.html",
            headers={"Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow"},
        )

    app.mount("/static", CachedStaticFiles(directory=STATIC_DIR), name="static")

    # Middleware runs bottom-up: the last added is the outermost.
    app.add_middleware(OriginCheckMiddleware)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=MAX_BODY_BYTES)
    if settings.allowed_hosts:
        # Loopback stays allowed so the container health check keeps working.
        hosts = [*settings.allowed_hosts, "127.0.0.1", "localhost"]
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=hosts)
    app.add_middleware(SecurityHeadersMiddleware, hsts=settings.cookie_secure)
    return app


app = create_app()
