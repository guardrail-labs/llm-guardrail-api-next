from __future__ import annotations

from typing import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class TenantBotMiddleware(BaseHTTPMiddleware):
    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        tenant = request.headers.get("X-Tenant") or request.headers.get("X-Tenant-ID")
        bot = request.headers.get("X-Bot") or request.headers.get("X-Bot-ID")
        request.state.tenant = tenant
        request.state.bot = bot
        return await call_next(request)
