# app/middleware/ingress_trace_guard.py
from __future__ import annotations

import re
import secrets
from typing import Awaitable, Callable, List, Tuple

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
    - Validates traceparent; drops invalid inbound header.
    - Ensures a safe X-Request-ID; rewrites inbound header to sanitized value.
    - Exposes request.state.request_id for downstream use.
    - On egress, always sets sanitized X-Request-ID.
      For traceparent: set only if inbound was valid and no downstream override.
    - Emits counters via trace_guard_violation_report(kind=...).
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        # Snapshot headers in a case-insensitive dict.
        headers = {k.lower(): v for k, v in request.headers.items()}

        # Validate inbound traceparent.
        tp_in = headers.get(_HDR_TRACEPARENT)
        tp_valid = bool(tp_in and _RE_TRACEPARENT.match(tp_in or ""))
        if tp_in is not None and not tp_valid:
            trace_guard_violation_report(kind="traceparent_invalid")

        # Normalize / create X-Request-ID.
        rid_in = headers.get(_HDR_REQ_ID)
        if rid_in is None or not _RE_REQ_ID.match(rid_in):
            kind = "request_id_new" if rid_in is None else "request_id_invalid"
            trace_guard_violation_report(kind=kind)
            rid = _new_request_id()
        else:
            rid = rid_in

        # Expose on request.state for downstream code.
        try:
            request.state.request_id = rid  # type: ignore[attr-defined]
        except Exception:
            # Best-effort only; do not fail request on state issues.
            pass

        # --- Rewrite inbound headers so downstream sees sanitized values ---
        scope_pairs: List[Tuple[bytes, bytes]] = list(
            request.scope.get("headers", [])
        )
        new_pairs: List[Tuple[bytes, bytes]] = []
        seen_req_id = False
        changed = False

        for kb, vb in scope_pairs:
            k = kb.decode("latin-1")
            v = vb.decode("latin-1")
            kl = k.lower()

            if kl == _HDR_TRACEPARENT:
                if tp_valid and tp_in:
                    val = tp_in.strip()
                    if v != val:
                        changed = True
                    new_pairs.append((kb, val.encode("latin-1")))
                else:
                    # Drop invalid traceparent entirely.
                    changed = True
                continue

            if kl == _HDR_REQ_ID:
                seen_req_id = True
                if v != rid:
                    changed = True
                # Canonicalize value; keep header name casing minimal.
                new_pairs.append(
                    (_HDR_REQ_ID.encode("latin-1"), rid.encode("latin-1"))
                )
                continue

            new_pairs.append((kb, vb))

        if not seen_req_id:
            changed = True
            new_pairs.append(
                (_HDR_REQ_ID.encode("latin-1"), rid.encode("latin-1"))
            )

        if changed:
            request.scope["headers"] = new_pairs
            # Invalidate Starlette's cached Headers object if present.
            if hasattr(request, "_headers"):
                try:
                    delattr(request, "_headers")
                except Exception:
                    pass

        # Call downstream stack.
        resp = await call_next(request)

        # --- Propagate sanitized headers on response ---
        # Always enforce sanitized request id.
        resp.headers["X-Request-ID"] = rid

        # Respect downstream traceparent override: only set if missing.
        existing_tp = resp.headers.get("traceparent")
        if not existing_tp and tp_valid and tp_in:
            resp.headers["traceparent"] = tp_in.strip()
        # If downstream set one, keep it regardless of inbound validity.

        return resp
