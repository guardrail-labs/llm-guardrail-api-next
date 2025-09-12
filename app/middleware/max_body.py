# app/middleware/max_body.py
# Summary (PR-L: Request size limit, opt-in):
# - Rejects oversized request bodies early with 413 JSON error.
# - Enabled when MAX_REQUEST_BYTES > 0.
# - Scope can be narrowed with MAX_REQUEST_BYTES_PATHS (csv of path prefixes).
# - Methods enforced: POST, PUT, PATCH.
#
# Response (413):
#   {"code": "payload_too_large", "detail": "...", "request_id": "<id>"}
#
# Notes:
# - Uses Content-Length when available (does not buffer the entire body).
# - Safe default is disabled (MAX_REQUEST_BYTES unset or <= 0).
# - Plays nice with existing JSON error shape used in tests.

from __future__ import annotations

import os
from typing import Awaitable, Callable, List

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from app.middleware.request_id import get_request_id

RequestHandler = Callable[[Request], Awaitable[Response]]


def _int_env(name: str, default: int = 0) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        val = int(float(raw.strip()))
        return val if val > 0 else 0
    except Exception:
        return 0


def _csv_env(name: str) -> List[str]:
    raw = os.getenv(name) or ""
    parts = [p.strip() for p in raw.replace(";", ",").replace(":", ",").split(",")]
    return [p for p in parts if p]


def _enabled() -> bool:
    return _int_env("MAX_REQUEST_BYTES", 0) > 0


def _limit_bytes() -> int:
    return _int_env("MAX_REQUEST_BYTES", 0)


def _path_prefixes() -> List[str]:
    # Default to "/" (apply everywhere) if not provided
    return _csv_env("MAX_REQUEST_BYTES_PATHS") or ["/"]


class _MaxBodyMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)
        self._limit = _limit_bytes()
        self._prefixes = _path_prefixes()
        self._methods = {"POST", "PUT", "PATCH"}

    async def dispatch(self, request: Request, call_next: RequestHandler) -> Response:
        if (
            self._limit > 0
            and request.method in self._methods
            and any(request.url.path.startswith(p) for p in self._prefixes)
        ):
            raw_len = request.headers.get("content-length")
            if raw_len:
                try:
                    n = int(raw_len)
                except Exception:
                    n = 0
                if n > self._limit:
                    return self._reject(n)
        return await call_next(request)

    def _reject(self, size: int) -> JSONResponse:
        rid = get_request_id() or ""
        detail = f"Request body too large ({size} bytes > {self._limit} bytes)."
        payload = {
            "code": "payload_too_large",
            "detail": detail,
            "request_id": rid,
        }
        # Minimal, consistent headers — X-Request-ID is asserted by tests elsewhere.
        headers = {"X-Request-ID": rid}
        return JSONResponse(payload, status_code=413, headers=headers)


def install_max_body_limit(app) -> None:
    if not _enabled():
        return
    app.add_middleware(_MaxBodyMiddleware)
