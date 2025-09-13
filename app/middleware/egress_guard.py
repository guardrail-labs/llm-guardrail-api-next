from __future__ import annotations

import json
import os

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response, StreamingResponse

from app.observability.metrics import inc_egress_redactions
from app.services.egress.modes import apply_egress_pipeline
from app.shared.headers import attach_guardrail_headers

ENABLED = os.getenv("EGRESS_FILTER_ENABLED", "1") == "1"


class EgressGuardMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        if not ENABLED:
            return response

        ctype = (response.headers.get("content-type") or "").lower()
        transfer_enc = (response.headers.get("transfer-encoding") or "").lower()

        # Never buffer/transform streaming responses
        if (
            isinstance(response, StreamingResponse)
            or "text/event-stream" in ctype
            or "chunked" in transfer_enc
        ):
            return response

        async def _set_body(b: bytes) -> None:
            async def _aiter():
                yield b

            response.headers["content-length"] = str(len(b))
            response.body_iterator = _aiter()  # type: ignore[attr-defined]

        # Buffer non-streaming response body
        body = b"".join([chunk async for chunk in response.body_iterator])  # type: ignore[attr-defined]

        if "application/json" in ctype:
            try:
                data = json.loads(body.decode("utf-8"))
            except Exception:
                await _set_body(body)
                return response

            processed, meta = apply_egress_pipeline(data)
            new_body = json.dumps(processed, ensure_ascii=False).encode("utf-8")

            # Coarse redaction count: 1 if body changed, else 0
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
                response.headers.setdefault(
                    "X-Guardrail-Egress-Policy-Status", meta["egress_policy_status"]
                )
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
                response.headers.setdefault(
                    "X-Guardrail-Egress-Policy-Status", meta["egress_policy_status"]
                )
            return response

        # Other content types passthrough
        await _set_body(body)
        return response

