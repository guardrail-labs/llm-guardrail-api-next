from __future__ import annotations

import json
import os

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response, StreamingResponse

from app.services.egress.filter import transform

# Toggle: enable/disable egress filtering (default on)
ENABLED = os.getenv("EGRESS_FILTER_ENABLED", "1") == "1"


class EgressGuardMiddleware(BaseHTTPMiddleware):
    """
    Egress filter that redacts/sanitizes non-streaming JSON and plaintext responses.

    IMPORTANT:
    - Streaming responses (StreamingResponse, SSE `text/event-stream`, or chunked Transfer-Encoding)
      are passed through untouched to preserve incremental delivery semantics.
    - Non-streaming responses are fully buffered, transformed, and reattached with a corrected
      Content-Length.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)

        if not ENABLED:
            return response

        ctype = (response.headers.get("content-type") or "").lower()
        transfer_enc = (response.headers.get("transfer-encoding") or "").lower()

        # P0 safety: never buffer/transform streaming responses
        # - OpenAI-style streams use StreamingResponse and/or text/event-stream
        # - Chunked transfer-encoding implies streaming/chunked delivery
        if (
            isinstance(response, StreamingResponse)
            or "text/event-stream" in ctype
            or "chunked" in transfer_enc
        ):
            return response

        async def _set_body(b: bytes) -> None:
            async def _aiter():
                yield b

            # Only safe for non-streaming responses; we control the full body buffer
            response.headers["content-length"] = str(len(b))
            # Reattach as an async iterator
            response.body_iterator = _aiter()  # type: ignore[attr-defined]

        # Only buffer non-streaming responses
        body = b"".join([chunk async for chunk in response.body_iterator])  # type: ignore[attr-defined]

        if "application/json" in ctype:
            try:
                data = json.loads(body.decode("utf-8"))
            except Exception:
                # Not valid JSON; restore original body and pass through
                await _set_body(body)
                return response

            new_data = transform(data)
            new_body = json.dumps(new_data, ensure_ascii=False).encode("utf-8")
            await _set_body(new_body)
            return response

        if "text/plain" in ctype:
            new_body = transform(body.decode("utf-8")).encode("utf-8")
            await _set_body(new_body)
            return response

        # Other content types: restore original body unmodified
        await _set_body(body)
        return response
