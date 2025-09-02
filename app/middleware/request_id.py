from __future__ import annotations

import uuid
from contextvars import ContextVar
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

# ContextVar to store per-request ID; exported for other modules if needed.
_REQUEST_ID_VAR: ContextVar[Optional[str]] = ContextVar("_REQUEST_ID_VAR", default=None)


def get_request_id() -> Optional[str]:
    """Return the current request id (if available)."""
    return _REQUEST_ID_VAR.get()


def _set_request_id(value: Optional[str]) -> None:
    _REQUEST_ID_VAR.set(value)


class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    Ensures every response has an X-Request-ID header.
    - If a client provides X-Request-ID, we propagate it.
    - Otherwise we generate a UUID4.
    Also stores the ID in a ContextVar for downstream access.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        _set_request_id(rid)
        try:
            response = await call_next(request)
        finally:
            # Clear the context for safety on ASGI reuse; set to None.
            _set_request_id(None)
        # Ensure header present on the way out.
        response.headers.setdefault("X-Request-ID", rid)
        return response
