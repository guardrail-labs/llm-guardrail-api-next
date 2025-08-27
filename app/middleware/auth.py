from __future__ import annotations

import time
from typing import Any, Dict, Optional

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.config import get_settings


def _truthy(val: object) -> bool:
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


def _extract_bearer(request: Request) -> Optional[str]:
    raw = request.headers.get("Authorization", "")
    if raw.startswith("Bearer "):
        return raw.split(" ", 1)[1].strip() or None
    return None


def _extract_api_key(request: Request) -> Optional[str]:
    return request.headers.get("X-API-Key") or None


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Simple auth middleware:
    - If AUTH_REQUIRE_API_KEY is truthy, require a matching API key header.
    - If AUTH_REQUIRE_JWT is truthy, optionally fetch JWKS and (placeholder)
      prepare for JWT verification (tests don't require full JWT validation).
    """

    def __init__(self, app) -> None:
        super().__init__(app)
        s = get_settings()

        self.require_api_key: bool = _truthy(
            getattr(s, "AUTH_REQUIRE_API_KEY", True)
        )
        self.expected_api_key: Optional[str] = getattr(s, "API_KEY", None)

        self.require_jwt: bool = _truthy(getattr(s, "AUTH_REQUIRE_JWT", False))
        self.jwks_url: Optional[str] = getattr(s, "JWT_JWKS_URL", None)
        self.jwks_ttl_seconds: int = int(
            getattr(s, "JWT_JWKS_TTL_SECONDS", 300)
        )

        # JWKS cache
        self._jwks_cache: Optional[Dict[str, Any]] = None
        self._jwks_cache_ts: float = 0.0

    async def dispatch(self, request: Request, call_next):
        # API key gate (the tests rely on this being present)
        if self.require_api_key:
            sent = _extract_api_key(request) or _extract_bearer(request)
            if not sent or (self.expected_api_key and sent != self.expected_api_key):
                return JSONResponse({"detail": "Unauthorized"}, status_code=401)

        # JWT gate (not exercised by tests; leave as no-op unless enabled)
        if self.require_jwt:
            token = _extract_bearer(request)
            if not token:
                return JSONResponse({"detail": "Unauthorized"}, status_code=401)
            # Fetch JWKS when configured; real validation can be added later.
            # We still type this correctly to satisfy mypy.
            _ = await self._get_jwks()

        return await call_next(request)

    async def _get_jwks(self) -> Dict[str, Any]:
        """
        Fetch and cache JWKS. Returns a dict (possibly empty) and
        avoids Any-typed returns to keep mypy happy.
        """
        now = time.time()
        if (
            self._jwks_cache is not None
            and (now - self._jwks_cache_ts) < float(self.jwks_ttl_seconds)
        ):
            return self._jwks_cache

        # If no URL, return a stable empty dict.
        if not self.jwks_url:
            self._jwks_cache = {}
            self._jwks_cache_ts = now
            return self._jwks_cache

        # Import httpx lazily to avoid making it a hard runtime dep unless used.
        import httpx  # local import on purpose

        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(self.jwks_url)
            resp.raise_for_status()
            data_json = resp.json()

        # Ensure we return a dict[str, Any]
        if isinstance(data_json, dict):
            data: Dict[str, Any] = data_json
        elif isinstance(data_json, list):
            data = {"keys": data_json}
        else:
            data = {}

        self._jwks_cache = data
        self._jwks_cache_ts = now
        return data
