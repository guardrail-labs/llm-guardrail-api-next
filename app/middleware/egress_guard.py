from __future__ import annotations

import json
import os

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from app.services.egress.filter import transform

ENABLED = os.getenv("EGRESS_FILTER_ENABLED", "1") == "1"

class EgressGuardMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        if not ENABLED:
            return response
        ctype = response.headers.get("content-type", "")

        async def _set_body(b: bytes) -> None:
            async def _aiter():
                yield b
            response.headers["content-length"] = str(len(b))
            response.body_iterator = _aiter()  # type: ignore[attr-defined]

        body = b"".join([chunk async for chunk in response.body_iterator])  # type: ignore[attr-defined]

        if "application/json" in ctype:
            try:
                data = json.loads(body.decode("utf-8"))
            except Exception:
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
        await _set_body(body)
        return response
