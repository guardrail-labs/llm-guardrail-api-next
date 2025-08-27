"""Request ID propagation utilities and middleware."""
from __future__ import annotations

import contextvars
import uuid
from typing import Optional

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

_REQUEST_ID = contextvars.ContextVar[Optional[str]]("request_id", default=None)
_HEADER = "X-Request-ID"


def get_request_id() -> Optional[str]:
    """Return the current request id stored in a ContextVar (if any)."""
    return _REQUEST_ID.get()


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Accept a caller-supplied request id or generate one and echo it back."""

    def __init__(self, app: ASGIApp, header_name: str = _HEADER) -> None:
        super().__init__(app)
        self.header_name = header_name

    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get(self.header_name) or str(uuid.uuid4())
        _REQUEST_ID.set(rid)

        response = await call_next(request)
        # Always echo the request id to the client
        response.headers[self.header_name] = rid
        return response
