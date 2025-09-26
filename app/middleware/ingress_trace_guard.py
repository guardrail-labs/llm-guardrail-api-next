from __future__ import annotations

import re
import secrets
from typing import Awaitable, Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.observability.metrics import trace_guard_violation_report

# RFC 9110 token rules are broader, but we constrain to hex+dash for safety.
# W3C traceparent: version-traceid-spanid-flags (hex with specific lengths).
_RE_TRACEPARENT = re.compile(
    r"^[ \t]*"
    r"(?P<ver>[0-9a-f]{2})-"
    r"(?P<traceid>[0-9a-f]{32})-"
    r"(?P<spanid>[0-9a-f]{16})-"
    r"(?P<flags>[0-9a-f]{2})"
    r"[ \t]*$"
)

# We accept 16..64 hex chars for request id (common proxies use 16/32/48/64).
_RE_REQ_ID = re.compile(r"^[a-f0-9]{16,64}$", re.IGNORECASE)

_HDR_REQ_ID = "x-request-id"
_HDR_TRACEPARENT = "traceparent"


def _new_request_id() -> str:
    # 16 bytes => 32 hex chars. Balanced collision resistance + readability.
    return secrets.token_hex(16)


class IngressTraceGuardMiddleware(BaseHTTPMiddleware):
    """
    - Validates traceparent; drops header if malformed.
    - Ensures X-Request-ID exists and matches a safe pattern.
    - Propagates sanitized X-Request-ID on response.
    - Emits Prometheus counters for drops/normalizations.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        # Work on a fresh header dict
        headers = {k.lower(): v for k, v in request.headers.items()}

        # 1) Validate traceparent strictly; drop if invalid
        tp = headers.get(_HDR_TRACEPARENT)
        if tp is not None and not _RE_TRACEPARENT.match(tp):
            trace_guard_violation_report(kind="traceparent_invalid")
            # We do not mutate the inbound request.headers object (Starlette cache),
            # but we do prevent further propagation by not copying it to response.
            headers.pop(_HDR_TRACEPARENT, None)

        # 2) Normalize / create X-Request-ID
        rid = headers.get(_HDR_REQ_ID)
        if rid is None or not _RE_REQ_ID.match(rid):
            trace_guard_violation_report(kind="request_id_new" if rid is None else "request_id_invalid")
            rid = _new_request_id()

        # Expose on request.state for downstream use
        try:
            request.state.request_id = rid  # type: ignore[attr-defined]
        except Exception:
            pass

        # Call downstream
        resp = await call_next(request)

        # 3) Propagate sanitized headers on response
        resp.headers.setdefault("X-Request-ID", rid)
        # Only add traceparent if a valid one came in; do not synthesize here.
        if tp and _RE_TRACEPARENT.match(tp):
            resp.headers.setdefault("traceparent", tp.strip())

        return resp
