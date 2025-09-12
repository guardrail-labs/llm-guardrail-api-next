# app/middleware/security_headers.py
# Summary (PR-K fix):
# - Enable security headers by default (tests expect 'nosniff' on /health).
# - Still allow disabling via SEC_HEADERS_ENABLED=0.
# - Typed request handler to keep mypy happy.

from __future__ import annotations

import os
from typing import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

RequestHandler = Callable[[Request], Awaitable[Response]]


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _str_env(name: str, default: str) -> str:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip()


def sec_headers_enabled() -> bool:
    # Default ON to satisfy baseline tests; allow opt-out with SEC_HEADERS_ENABLED=0.
    return _bool_env("SEC_HEADERS_ENABLED", True)


class _SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)
        self._frame_deny = _bool_env("SEC_HEADERS_FRAME_DENY", True)
        self._nosniff = _bool_env("SEC_HEADERS_CONTENT_TYPE_NOSNIFF", True)
        self._perm = _str_env("SEC_HEADERS_PERMISSIONS_POLICY", "geolocation=()")
        self._hsts = _bool_env("SEC_HEADERS_HSTS", False)
        self._hsts_value = _str_env(
            "SEC_HEADERS_HSTS_VALUE",
            "max-age=31536000; includeSubDomains",
        )

    async def dispatch(self, request: Request, call_next: RequestHandler) -> Response:
        resp = await call_next(request)
        if self._frame_deny:
            resp.headers.setdefault("X-Frame-Options", "DENY")
        if self._nosniff:
            resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        if self._perm:
            resp.headers.setdefault("Permissions-Policy", self._perm)
        if self._hsts:
            resp.headers.setdefault("Strict-Transport-Security", self._hsts_value)
        return resp


def install_security_headers(app) -> None:
    if not sec_headers_enabled():
        return
    app.add_middleware(_SecurityHeadersMiddleware)
