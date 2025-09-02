# app/middleware/request_id.py
from __future__ import annotations
import uuid
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        # make available to downstream
        request.state.request_id = rid
        response: Response = await call_next(request)
        # ensure header on ALL responses (200/4xx/5xx)
        response.headers["X-Request-ID"] = rid
        return response
