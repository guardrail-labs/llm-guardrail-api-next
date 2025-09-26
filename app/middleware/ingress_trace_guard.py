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
    - Rewrites inbound headers so downstream sees sanitized values.
    - Sets sanitized X-Request-ID on response; only propagates valid traceparent.
    - Emits Prometheus counters for drops/normalizations.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        # Snapshot header values
        headers = {k.lower(): v for k, v in request.headers.items()}

        # Validate traceparent strictly
        tp_in = headers.get(_HDR_TRACEPARENT)
        tp_valid = bool(tp_in and _RE_TRACEPARENT.match(tp_in or ""))
        if tp_in is not None and not tp_valid:
            trace_guard_violation_report(kind="traceparent_invalid")

        # Normalize / create X-Request-ID
        rid_in = headers.get(_HDR_REQ_ID)
        if rid_in is None or not _RE_REQ_ID.match(rid_in):
            kind = "request_id_new" if rid_in is None else "request_id_invalid"
            trace_guard_violation_report(kind=kind)
            rid = _new_request_id()
        else:
            rid = rid_in

        # Expose on request.state for downstream use
        try:
            request.state.request_id = rid
        except Exception:
            pass

        # --- Rewrite inbound request headers so downstream sees sanitized values ---
        scope_pairs = request.scope.get("headers", [])
        new_pairs: list[tuple[bytes, bytes]] = []
        seen_req_id = False
        changed = False

        for kb, vb in scope_pairs:
            k = kb.decode("latin-1")
            v = vb.decode("latin-1")
            kl = k.lower()

            if kl == _HDR_TRACEPARENT:
                if tp_valid and tp_in:
                    # Normalize whitespace for traceparent
                    val = tp_in.strip()
                    if v != val:
                        changed = True
                    new_pairs.append((kb, val.encode("latin-1")))
                else:
                    # Drop invalid traceparent
                    changed = True
                continue

            if kl == _HDR_REQ_ID:
                seen_req_id = True
                if v != rid:
                    changed = True
                # Use canonical header name but keep original casing for safety
                new_pairs.append((_HDR_REQ_ID.encode("latin-1"), rid.encode("latin-1")))
                continue

            new_pairs.append((kb, vb))

        if not seen_req_id:
            changed = True
            new_pairs.append((_HDR_REQ_ID.encode("latin-1"), rid.encode("latin-1")))

        if changed:
            request.scope["headers"] = new_pairs
            # Invalidate Starlette's cached Headers so downstream sees updates
            if hasattr(request, "_headers"):
                try:
                    delattr(request, "_headers")  # type: ignore[attr-defined]
                except Exception:
                    pass

        # Call downstream
        resp = await call_next(request)

        # --- Propagate sanitized headers on response ---
        resp.headers["X-Request-ID"] = rid
        if tp_valid and tp_in:
            resp.headers["traceparent"] = tp_in.strip()
        else:
            # Ensure invalid traceparent is not leaked on egress
            resp.headers.pop("traceparent", None)

        return resp
