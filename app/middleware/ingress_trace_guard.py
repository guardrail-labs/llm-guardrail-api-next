# app/middleware/ingress_trace_guard.py
from __future__ import annotations

import re
import uuid
from typing import Awaitable, Callable, Dict, List, Tuple

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.observability.metrics import (
    _limit_tenant_bot_labels,
    ingress_invalid_traceparent,
    ingress_reqid_generated,
    trace_guard_violation_report,
)

# W3C traceparent: version-traceid-spanid-flags (lower-hex, fixed lengths).
_RE_TRACEPARENT = re.compile(
    r"^[ \t]*"
    r"(?P<ver>[0-9a-f]{2})-"
    r"(?P<traceid>[0-9a-f]{32})-"
    r"(?P<spanid>[0-9a-f]{16})-"
    r"(?P<flags>[0-9a-f]{2})"
    r"[ \t]*$"
)

# Allow common hex-ids and UUIDs, but only *log* if they don't match.
_RE_REQ_ID = re.compile(
    r"^(?:[a-f0-9]{16,64}|"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12})$",
    re.IGNORECASE,
)

_HDR_REQ_ID = "x-request-id"
_HDR_TRACEPARENT = "traceparent"


def _tenant_bot_from_headers(request: Request) -> tuple[str, str]:
    canon: Dict[str, str] = getattr(request.state, "headers_canon", {}) or {}
    tenant = canon.get("X-Guardrail-Tenant") or request.headers.get("X-Guardrail-Tenant", "")
    bot = canon.get("X-Guardrail-Bot") or request.headers.get("X-Guardrail-Bot", "")
    return _limit_tenant_bot_labels(tenant or "", bot or "")


def _new_request_id() -> str:
    # Tests require a proper UUID format when we generate a request id.
    return str(uuid.uuid4())


class IngressTraceGuardMiddleware(BaseHTTPMiddleware):
    """
    - Validates inbound traceparent; drops invalid before downstream sees it.
    - Logs violations for malformed X-Request-ID but *does not replace it*.
    - If X-Request-ID is missing, generates a UUID4 and injects it.
    - Exposes request.state.request_id.
    - On egress, only sets headers if missing to preserve downstream overrides.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        headers = {k.lower(): v for k, v in request.headers.items()}
        canon: Dict[str, str] = getattr(request.state, "headers_canon", {}) or {}

        # --- traceparent validation (inbound rewrite/drop) ---
        tp_in = canon.get("traceparent") or headers.get(_HDR_TRACEPARENT)
        tp_valid = bool(tp_in and _RE_TRACEPARENT.match(tp_in or ""))
        if tp_in is not None and not tp_valid:
            trace_guard_violation_report(kind="traceparent_invalid")
            tenant, bot = _tenant_bot_from_headers(request)
            ingress_invalid_traceparent.labels(tenant=tenant, bot=bot).inc()

        # --- request id handling ---
        rid_in = canon.get("X-Request-ID") or headers.get(_HDR_REQ_ID)
        if rid_in is None:
            trace_guard_violation_report(kind="request_id_new")
            tenant, bot = _tenant_bot_from_headers(request)
            ingress_reqid_generated.labels(tenant=tenant, bot=bot).inc()
            rid = _new_request_id()
            rid_missing = True
        else:
            rid = rid_in
            rid_missing = False
            if not _RE_REQ_ID.match(rid_in):
                trace_guard_violation_report(kind="request_id_invalid")

        # Stash for downstream code.
        try:
            request.state.request_id = rid
        except Exception:
            pass
        try:
            request.scope["request_id"] = rid
        except Exception:
            pass

        # --- rewrite inbound headers for downstream ---
        scope_pairs: List[Tuple[bytes, bytes]] = list(request.scope.get("headers", []))
        new_pairs: List[Tuple[bytes, bytes]] = []
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
                    # Drop invalid inbound traceparent entirely.
                    changed = True
                continue

            if kl == _HDR_REQ_ID:
                # Do not override client-supplied request id even if malformed.
                new_pairs.append((kb, vb))
                continue

            new_pairs.append((kb, vb))

        if rid_missing:
            changed = True
            new_pairs.append((_HDR_REQ_ID.encode("latin-1"), rid.encode("latin-1")))

        if changed:
            request.scope["headers"] = new_pairs
            if hasattr(request, "_headers"):
                try:
                    delattr(request, "_headers")
                except Exception:
                    pass

        # --- downstream ---
        resp = await call_next(request)

        # --- egress propagation preserving downstream overrides ---
        if "X-Request-ID" not in resp.headers:
            resp.headers["X-Request-ID"] = rid

        if "traceparent" not in resp.headers and tp_valid and tp_in:
            resp.headers["traceparent"] = tp_in.strip()

        return resp
