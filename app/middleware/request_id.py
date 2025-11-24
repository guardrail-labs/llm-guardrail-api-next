from __future__ import annotations

import uuid
from contextvars import ContextVar
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

# Context variable for request id
_REQUEST_ID: ContextVar[Optional[str]] = ContextVar("request_id", default=None)

_HEADER = "X-Request-ID"


def get_request_id() -> Optional[str]:
    """
    Return the current request id (if any) set by RequestIDMiddleware.
    """
    return _REQUEST_ID.get()


class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    Ensures every request has a stable request id:
    - Accept an incoming X-Request-ID if present.
    - Otherwise generate a new UUID4.
    - Expose it via contextvar for other modules (logging/tracing).
    - Echo it back on the response headers.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint,
    ) -> Response:
        # Ingest or generate.
        raw_header = request.headers.get(_HEADER)

        if raw_header is None:
            # No header provided: generate a new ID.
            rid = str(uuid.uuid4())
        else:
            # Header provided: normalize for internal use.
            trimmed = raw_header.strip()
            if trimmed:
                rid = trimmed
            else:
                # Header is all whitespace; fall back to generated ID.
                rid = str(uuid.uuid4())

        token = _REQUEST_ID.set(rid)
        try:
            try:
                request.state.request_id = rid
            except Exception:
                pass
            try:
                request.scope["request_id"] = rid
            except Exception:
                pass
            response: Response = await call_next(request)
        finally:
            # Always reset contextvar to avoid leakage across requests.
            _REQUEST_ID.reset(token)

        # Ensure header is present on the response:
        # - If the client sent a header, leave it exactly as-is.
        # - Otherwise, emit the normalized/generated ID.
        if response.headers.get(_HEADER) is None:
            if raw_header is not None:
                response.headers[_HEADER] = raw_header
            else:
                response.headers[_HEADER] = rid

        return response
