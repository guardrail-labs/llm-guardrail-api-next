"""
Max request body guard.

Env (read per request):
- MAX_REQUEST_BYTES: if set and Content-Length exceeds, return 413 early.
"""

from __future__ import annotations

import os
from typing import Awaitable, Callable, Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.middleware.request_id import get_request_id


def _limit() -> Optional[int]:
    val = os.getenv("MAX_REQUEST_BYTES")
    if not val:
        return None
    try:
        n = int(val)
        return n if n > 0 else None
    except Exception:
        return None


class _MaxBodyMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        lim = _limit()
        if lim is not None:
            try:
                clen = int(request.headers.get("content-length") or "0")
            except Exception:
                clen = 0
            if clen > lim:
                payload = {
                    "code": "payload_too_large",
                    "detail": "Payload too large",
                    "request_id": get_request_id() or "",
                }
                return JSONResponse(payload, status_code=413)

        resp: Response = await call_next(request)
        return resp


def install_max_body(app) -> None:
    app.add_middleware(_MaxBodyMiddleware)
