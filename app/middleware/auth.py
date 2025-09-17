from __future__ import annotations

import os
import uuid

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

# Paths that bypass auth entirely (exact match)
_SAFE_PATHS: set[str] = {"/health", "/healthz", "/readyz", "/livez", "/metrics"}

# Prefixes that bypass auth.  Our OpenAI-compatible routes live under ``/v1``
# and are intentionally unauthenticated to mimic the upstream API contract.
_SAFE_PREFIXES: tuple[str, ...] = ("/v1/",)


def _is_auth_disabled() -> bool:
    return (os.environ.get("GUARDRAIL_DISABLE_AUTH") or "0") == "1"


def _is_safe_path(path: str) -> bool:
    """Return True if the request path should bypass auth."""
    if path in _SAFE_PATHS:
        return True
    return any(path.startswith(pfx) for pfx in _SAFE_PREFIXES)


def _has_auth_header(request: Request) -> bool:
    return bool(request.headers.get("X-API-Key") or request.headers.get("Authorization"))


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Uniform API key/Authorization gate for the whole app.
    Exemptions:
      - OPTIONS preflight
      - Probe endpoints (/health, /healthz, /readyz, /livez, /metrics)
    You can bypass entirely via GUARDRAIL_DISABLE_AUTH=1 (used by CI when needed).
    """

    async def dispatch(self, request: Request, call_next):
        # Allow preflight and safe paths
        if request.method == "OPTIONS" or _is_safe_path(request.url.path):
            return await call_next(request)

        # Optional global bypass
        if _is_auth_disabled():
            return await call_next(request)

        if _has_auth_header(request):
            return await call_next(request)

        # 401 JSON error aligned with other handlers
        rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        resp = JSONResponse(
            status_code=401,
            content={"detail": "Unauthorized", "request_id": rid},
        )
        resp.headers["WWW-Authenticate"] = "Bearer"
        resp.headers["X-Request-ID"] = rid
        return resp
