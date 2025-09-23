from __future__ import annotations

import logging
import os
from typing import Awaitable, Callable, Optional, TypeVar

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response


_log = logging.getLogger(__name__)

T = TypeVar("T")


def _best_effort(msg: str, fn: Callable[[], T], default: Optional[T] = None) -> Optional[T]:
    try:
        return fn()
    except Exception as exc:  # pragma: no cover
        # nosec B110 - defensive; body size tracking must not crash requests
        _log.debug("%s: %s", msg, exc)
        return default


def _limit() -> Optional[int]:
    raw = (os.getenv("MAX_REQUEST_BYTES") or "").strip()
    if not raw:
        return None

    def _coerce() -> Optional[int]:
        v = int(raw)
        return v if v > 0 else None

    return _best_effort("parse MAX_REQUEST_BYTES", _coerce, default=None)


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
            def _parse_content_length() -> int:
                return int(cl)

            size = _best_effort("parse content-length", _parse_content_length)
            if size is not None and size > self._limit:
                # return 413 regardless of route/method
                return JSONResponse({"code": "payload_too_large"}, status_code=413)

        return await call_next(request)


def install_max_body(app) -> None:
    if _limit() is not None:
        app.add_middleware(MaxBodyMiddleware)

