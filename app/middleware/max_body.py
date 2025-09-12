# app/middleware/max_body.py
# Summary (PR-T): Install an optional max request body size limiter.
# - Reads MAX_REQUEST_BYTES (default 0 => disabled).
# - If Content-Length > limit => respond 413 early.
# - Minimal, dependency-free, and mypy/ruff clean.

from __future__ import annotations

from typing import Awaitable, Callable, Optional

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from app.services.config_sanitizer import get_int


def _read_limit_bytes() -> int:
    # Accept ints/float strings; clamp to >= 0
    return get_int("MAX_REQUEST_BYTES", default=0, min_value=0)


class _MaxBodyMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, limit_bytes: int) -> None:
        super().__init__(app)
        self._limit = max(0, int(limit_bytes))

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if self._limit <= 0:
            return await call_next(request)

        # Use Content-Length if present; for unknown/chunked bodies, we allow
        # to keep this middleware cheap and non-invasive.
        cl_header: Optional[str] = request.headers.get("content-length")
        if cl_header is not None:
            try:
                content_len = int(float(cl_header.strip()))
            except Exception:
                content_len = 0
            if content_len > self._limit:
                # Return a simple, consistent JSON payload.
                # (main.py has its own error shaper for some statuses; 413 here is sufficient.)
                return JSONResponse(
                    {"code": "payload_too_large", "detail": "request body too large"},
                    status_code=413,
                )

        return await call_next(request)


def install_max_body(app: FastAPI) -> None:
    limit = _read_limit_bytes()
    if limit > 0:
        app.add_middleware(_MaxBodyMiddleware, limit_bytes=limit)
