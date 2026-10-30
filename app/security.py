"""Pure-ASGI security middleware: headers, origin checks and body size limits."""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

CSP = "; ".join(
    [
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "manifest-src 'self'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ]
)

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


async def _send_json(send: Send, status: int, detail: str) -> None:
    body = json.dumps({"detail": detail}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"cache-control", b"no-store"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp, *, hsts: bool) -> None:
        self.app = app
        self.hsts = hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["Content-Security-Policy"] = CSP
                headers["X-Content-Type-Options"] = "nosniff"
                headers["X-Frame-Options"] = "DENY"
                headers["Referrer-Policy"] = "no-referrer"
                headers["Permissions-Policy"] = (
                    "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()"
                )
                headers["Cross-Origin-Opener-Policy"] = "same-origin"
                headers["Cross-Origin-Resource-Policy"] = "same-origin"
                if self.hsts:
                    headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
                if scope["path"].startswith("/api/") and "cache-control" not in headers:
                    headers["Cache-Control"] = "no-store"
            await send(message)

        await self.app(scope, receive, send_wrapper)


class OriginCheckMiddleware:
    """Reject cross-site state-changing requests (defence in depth next to CSRF tokens).

    Browsers always send Origin on cross-origin POST/PUT/DELETE; if it is present
    it must match the Host the request was sent to. Writes must also be JSON,
    which HTML forms cannot produce without a CORS preflight.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] in SAFE_METHODS:
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        origin = headers.get("origin")
        if origin is not None:
            host = headers.get("host", "")
            if origin == "null" or urlsplit(origin).netloc.lower() != host.lower():
                await _send_json(send, 403, "Cross-origin request blocked")
                return
        if headers.get("sec-fetch-site") in {"cross-site", "same-site"}:
            await _send_json(send, 403, "Cross-site request blocked")
            return
        content_type = headers.get("content-type", "")
        has_body = headers.get("content-length", "0") != "0" or "transfer-encoding" in headers
        if has_body and not content_type.split(";")[0].strip().lower() == "application/json":
            await _send_json(send, 415, "Content-Type must be application/json")
            return
        await self.app(scope, receive, send)


class BodySizeLimitMiddleware:
    def __init__(self, app: ASGIApp, *, max_bytes: int, overrides: dict[str, int] | None = None) -> None:
        self.app = app
        self.max_bytes = max_bytes
        # Exact request paths that may send a different maximum.
        self.overrides = overrides or {}

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        max_bytes = self.overrides.get(scope["path"], self.max_bytes)
        length = Headers(scope=scope).get("content-length")
        if length is not None:
            try:
                too_big = int(length) > max_bytes
            except ValueError:
                too_big = True
            if too_big:
                await _send_json(send, 413, "Request body too large")
                return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > max_bytes:
                    raise _BodyTooLarge
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _BodyTooLarge:
            await _send_json(send, 413, "Request body too large")


class _BodyTooLarge(Exception):
    pass
