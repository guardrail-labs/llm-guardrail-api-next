from __future__ import annotations

import json
from typing import Any, Awaitable, Callable, Dict

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.observability.metrics import unicode_ingress_report
from app.sanitizers.unicode_sanitizer import sanitize_payload

# Header names used elsewhere in the API for label scoping
_HDR_TENANT = "X-Guardrail-Tenant"
_HDR_BOT = "X-Guardrail-Bot"


class UnicodeIngressSanitizer(BaseHTTPMiddleware):
    """
    Middleware that sanitizes inbound JSON payloads:
     - NFKC normalization
     - Removal of zero-width and bidi control chars
     - Basic homoglyph mapping (Cyrillic/Greek → ASCII)
    Emits Prometheus counters with tenant/bot label limiting.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        # Extract labels (best-effort)
        tenant = request.headers.get(_HDR_TENANT, "")
        bot = request.headers.get(_HDR_BOT, "")

        content_type = request.headers.get("content-type", "")
        if "application/json" not in content_type.lower():
            # Non-JSON: pass through (we can extend later for form-data/OCR)
            return await call_next(request)

        # Read body once, sanitize, and re-inject
        raw = await request.body()
        if not raw:
            return await call_next(request)

        try:
            data = json.loads(raw)
        except Exception:
            # If invalid JSON, don't mutate; let downstream error handlers respond.
            return await call_next(request)

        sanitized, stats = sanitize_payload(data)
        # Emit metrics
        unicode_ingress_report(
            tenant=tenant,
            bot=bot,
            strings_seen=stats.get("strings_seen", 0),
            zero_width_removed=stats.get("zero_width_removed", 0),
            bidi_controls_removed=stats.get("bidi_controls_removed", 0),
            confusables_mapped=stats.get("confusables_mapped", 0),
            mixed_scripts=stats.get("mixed_scripts", 0),
        )

        # If unchanged, pass through original request
        if stats.get("strings_changed", 0) == 0:
            return await call_next(request)

        new_body = json.dumps(sanitized).encode("utf-8")

        async def receive() -> Dict[str, Any]:
            return {"type": "http.request", "body": new_body, "more_body": False}

        # Rebuild request with sanitized body
        new_request = Request(request.scope, receive)
        return await call_next(new_request)
