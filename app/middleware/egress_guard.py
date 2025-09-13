from __future__ import annotations

import json
import os

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response, StreamingResponse

from app.services.egress.modes import apply_egress_pipeline
from app.services.egress.filter import DEFAULT_REDACTIONS
from app.services.rulepacks_engine import (
    egress_redactions,
    egress_mode,
    rulepacks_enabled,
)
from app.services.egress.stream_redactor import wrap_streaming_iterator
from app.shared.headers import attach_guardrail_headers
from app.observability.metrics import inc_egress_redactions

ENABLED = os.getenv("EGRESS_FILTER_ENABLED", "1") == "1"
STREAMING_REDACT_ENABLED = os.getenv("EGRESS_STREAMING_REDACT_ENABLED", "0") == "1"
STREAMING_OVERLAP_CHARS = int(os.getenv("EGRESS_STREAMING_OVERLAP_CHARS", "2048"))

# For SSE, enforce a safer minimum window to avoid splitting common secrets/tokens.
# Tests may set STREAMING_OVERLAP_CHARS to small values; this guard preserves correctness.
SSE_MIN_WINDOW = int(os.getenv("EGRESS_SSE_MIN_WINDOW", "128"))


class EgressGuardMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)
        if not ENABLED:
            return response

        ctype = (response.headers.get("content-type") or "").lower()
        transfer_enc = (response.headers.get("transfer-encoding") or "").lower()

        # --- Streaming path ---
        if (
            isinstance(response, StreamingResponse)
            or "text/event-stream" in ctype
            or "chunked" in transfer_enc
        ):
            if STREAMING_REDACT_ENABLED and ("text/" in ctype or "event-stream" in ctype):
                redactions = DEFAULT_REDACTIONS
                if rulepacks_enabled() and egress_mode() == "enforce":
                    rp = egress_redactions()
                    if rp:
                        redactions = redactions + rp

                original_iter = response.body_iterator  # type: ignore[attr-defined]

                # Pick overlap; enforce a higher floor for SSE to capture tokens within one window.
                overlap = STREAMING_OVERLAP_CHARS
                if "event-stream" in ctype:
                    overlap = max(overlap, SSE_MIN_WINDOW)

                async def _on_complete(changed: int) -> None:
                    if changed > 0:
                        inc_egress_redactions("text/stream", changed)

                response.body_iterator = wrap_streaming_iterator(  # type: ignore[attr-defined]
                    original_iter,
                    redactions,
                    overlap_chars=overlap,
                    on_complete=_on_complete,
                )

                # Informational: stream is being filtered (counts via metrics)
                response.headers.setdefault("X-Guardrail-Streaming-Redactor", "enabled")

                attach_guardrail_headers(
                    response,
                    decision="allow",
                    ingress_action="allow",
                    egress_action="allow",
                )
                return response

            return response

        # --- Non-streaming path (buffer, transform) ---
        async def _set_body(b: bytes) -> None:
            async def _aiter():
                yield b

            response.headers["content-length"] = str(len(b))
            response.body_iterator = _aiter()  # type: ignore[attr-defined]

        # Buffer non-streaming response body
        body = b"".join(
            [chunk async for chunk in response.body_iterator]  # type: ignore[attr-defined]
        )

        if "application/json" in ctype:
            try:
                data = json.loads(body.decode("utf-8"))
            except Exception:
                await _set_body(body)
                return response

            processed, meta = apply_egress_pipeline(data)
            new_body = json.dumps(processed, ensure_ascii=False).encode("utf-8")

            if new_body != body:
                inc_egress_redactions("application/json", 1)

            await _set_body(new_body)
            attach_guardrail_headers(
                response,
                decision="allow",
                ingress_action="allow",
                egress_action="allow",
            )
            if meta.get("egress_policy_status"):
                status_val = meta["egress_policy_status"]
                response.headers.setdefault("X-Guardrail-Egress-Policy-Status", status_val)
            return response

        if "text/plain" in ctype:
            text = body.decode("utf-8")
            processed, meta = apply_egress_pipeline(text)
            new_text = processed if isinstance(processed, str) else str(processed)
            new_body = new_text.encode("utf-8")

            if new_body != body:
                inc_egress_redactions("text/plain", 1)

            await _set_body(new_body)
            attach_guardrail_headers(
                response,
                decision="allow",
                ingress_action="allow",
                egress_action="allow",
            )
            if meta.get("egress_policy_status"):
                status_val = meta["egress_policy_status"]
                response.headers.setdefault("X-Guardrail-Egress-Policy-Status", status_val)
            return response

        await _set_body(body)
        return response
