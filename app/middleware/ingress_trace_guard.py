from __future__ import annotations

import re
import secrets
from typing import Awaitable, Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.observability.metrics import trace_guard_violation_report

# W3C traceparent: version-traceid-spanid-flags (lower-hex, fixed lengths).
_RE_TRACEPARENT = re.compile(
    r"^[ \t]*"
    r"(?P<ver>[0-9a-f]{2})-"
    r"(?P<traceid>[0-9a-f]{32})-"
    r"(?P<spanid>[0-9a-f]{16})-"
    r"(?P<flags>[0-9a-f]{2})"
    r"[ \t]*$"
)

# Accept 16..64 hex chars for request id (covers common proxy formats).
_RE_REQ_ID = re.compile(r"^[a-f0-9]{16,64}$", re.IGNORECASE)

_HDR_REQ_ID = "x-request-id"
_HDR_TRACEPARENT = "traceparent"


def _new_request_id() -> str:
    # 16 bytes => 32 hex chars.
    return secrets.token_hex(16)


class IngressTraceGuardMiddleware(BaseHTTPMiddleware):
    """
    - Validates traceparent; drops header if malformed.
    - Ensures X-Request-ID exists and matches a safe pattern.
    - Exposes request.state.request_id and sets X-Request-ID on response.
    - Emits Prometheus counters for drops/normalizations.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        # Snapshot header values; do not mutate Starlette's cached headers.
        headers = {k.lower(): v for k, v in request.headers.items()}

        # 1) Validate traceparent strictly; drop if invalid
        tp = headers.get(_HDR_TRACEPARENT)
        tp_valid = bool(tp and _RE_TRACEPARENT.match(tp or ""))
        if tp is not None and not tp_valid:
            trace_guard_violation_report(kind="traceparent_invalid")
            # We avoid propagating invalid traceparent on the response.

        # 2) Normalize / create X-Request-ID
        rid = headers.get(_HDR_REQ_ID)
        if rid is None or not _RE_REQ_ID.match(rid):
            kind = "request_id_new" if rid is None else "request_id_invalid"
            trace_guard_violation_report(kind=kind)
            rid = _new_request_id()

        # Expose on request.state for downstream use
        try:
            request.state.request_id = rid
        except Exception:
            pass

        # Call downstream
        resp = await call_next(request)

        # 3) Propagate sanitized headers on response
        resp.headers.setdefault("X-Request-ID", rid)
        if tp_valid and tp:
            resp.headers.setdefault("traceparent", tp.strip())

        return resp
