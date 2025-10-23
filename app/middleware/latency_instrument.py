from __future__ import annotations

from starlette.types import ASGIApp, Receive, Scope, Send

from app.metrics.latency import observe


class LatencyMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "?")
        method = scope.get("method", "?")
        with observe(path, method):
            await self.app(scope, receive, send)
