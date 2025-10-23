from __future__ import annotations

import re

from starlette.types import ASGIApp, Receive, Scope, Send

from app.metrics.latency import observe

# Prefer shared normalizer if present
try:  # pragma: no cover - exercised indirectly if module exists
    from app.metrics.route_label import route_label as _route_label
except Exception:  # pragma: no cover
    _UUID_RE = re.compile(
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
        r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
    )
    _HEX_RE = re.compile(r"^[0-9a-fA-F]{8,}$")
    _NUM_RE = re.compile(r"^[0-9]{4,}$")
    _ULID_RE = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")

    def _route_label(path: str) -> str:
        segs = []
        for s in path.split("/"):
            if not s:
                continue
            if _UUID_RE.match(s) or _ULID_RE.match(s):
                segs.append(":id")
            elif len(s) > 32:
                segs.append(":seg")
            elif _NUM_RE.match(s) or _HEX_RE.match(s):
                segs.append(":id")
            else:
                segs.append(s)
        return "/" + "/".join(segs) if segs else "/"


class LatencyMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        raw_path = scope.get("path", "?")
        path = _route_label(raw_path)
        method = scope.get("method", "?")
        with observe(path, method):
            await self.app(scope, receive, send)
