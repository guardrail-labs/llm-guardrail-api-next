# app/middleware/nosniff.py
# Summary (PR-K mypy fix):
# - Type the request handler so Response isn't inferred as Any.
# - Middleware always adds X-Content-Type-Options: nosniff (setdefault).

from __future__ import annotations

from typing import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

RequestHandler = Callable[[Request], Awaitable[Response]]


class _NoSniffMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestHandler) -> Response:
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        return resp


def install_nosniff(app) -> None:
    app.add_middleware(_NoSniffMiddleware)
