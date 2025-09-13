from __future__ import annotations

import os
from typing import Awaitable, Callable

from fastapi import Request
from fastapi import FastAPI
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response


def _truthy(v: object) -> bool:
    return str(v).strip().lower() in {"1", "true", "yes", "on"}


class _SecurityHeaders(BaseHTTPMiddleware):
    def __init__(self, app: FastAPI) -> None:
        super().__init__(app)
        # Back-compat + sensible defaults for tests
        self._xfo_val = os.getenv("SEC_HEADERS_XFO", "DENY")
        self._nosniff_enabled = _truthy(os.getenv("SEC_HEADERS_NOSNIFF_ENABLED", "1"))
        # Preserve legacy env alias if present for referrer policy
        self._referrer = os.getenv(
            "SEC_HEADERS_REFERRER_POLICY",
            os.getenv("REFERRER_POLICY_VALUE", "no-referrer"),
        )
        self._permissions = os.getenv("PERMISSIONS_POLICY", "geolocation=()")

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        resp = await call_next(request)

        # Always set these for tests
        resp.headers.setdefault("X-Frame-Options", self._xfo_val)
        if self._nosniff_enabled:
            resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        if self._referrer:
            resp.headers.setdefault("Referrer-Policy", self._referrer)
        if self._permissions:
            resp.headers.setdefault("Permissions-Policy", self._permissions)

        return resp


def install_security_headers(app: FastAPI) -> None:
    app.add_middleware(_SecurityHeaders)
