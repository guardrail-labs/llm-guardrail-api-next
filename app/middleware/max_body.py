from __future__ import annotations

import os
from typing import Awaitable, Callable, Optional

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response


def _limit() -> Optional[int]:
    raw = (os.getenv("MAX_REQUEST_BYTES") or "").strip()
    if not raw:
        return None
    try:
        v = int(raw)
        return v if v > 0 else None
    except Exception:
        return None


class MaxBodyMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self._enabled = True  # enabled if limit present
        self._limit = _limit()

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if not self._limit:
            return await call_next(request)

        cl = request.headers.get("content-length")
        if cl:
            try:
                size = int(cl)
            except Exception:
                size = None
            if size is not None and size > self._limit:
                # return 413 regardless of route/method
                return JSONResponse({"code": "payload_too_large"}, status_code=413)

        return await call_next(request)


def install_max_body(app) -> None:
    if _limit() is not None:
        app.add_middleware(MaxBodyMiddleware)

