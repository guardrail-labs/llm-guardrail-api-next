from __future__ import annotations

from typing import Dict, Mapping

from starlette.requests import Request
from starlette.types import ASGIApp, Receive, Scope, Send

_CANON = {
    "x-request-id": "X-Request-ID",
    "traceparent": "traceparent",
    "x-guardrail-tenant": "X-Guardrail-Tenant",
    "x-guardrail-bot": "X-Guardrail-Bot",
}


def _canon_name(name: str) -> str:
    low = name.strip().lower()
    if not low:
        return ""
    if low in _CANON:
        return _CANON[low]
    parts = [part.capitalize() for part in low.split("-") if part]
    return "-".join(parts) if parts else low


def canonicalize(headers: Mapping[str, str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for key, value in headers.items():
        canon_key = _canon_name(key)
        if not canon_key:
            continue
        canon_val = value.strip().replace("\r", "").replace("\n", "")
        if "  " in canon_val:
            canon_val = " ".join(canon_val.split())
        out[canon_key] = canon_val
    return out


class HeaderCanonicalizeMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope, receive=receive)
        canon = canonicalize(request.headers)
        setattr(request.state, "headers_canon", canon)
        await self.app(scope, receive, send)
