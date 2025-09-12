# app/middleware/nosniff.py
# Summary (PR-K: ensure 'nosniff' header baseline):
# - Lightweight middleware that always adds X-Content-Type-Options: nosniff.
# - This guarantees the baseline test on /health passes regardless of other gates.
# - Safe to stack with security_headers middleware (setdefault prevents clobber).

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp


class _NoSniffMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        return resp


def install_nosniff(app) -> None:
    app.add_middleware(_NoSniffMiddleware)
