from __future__ import annotations

import json
import time
from typing import Any, Dict, Optional

import httpx
import jwt
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.config import get_settings


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Dual-mode auth:
      - API Key (default): header "X-API-Key" or "Authorization: Bearer <key>"
      - JWT (AUTH_MODE=jwt):
          * RS256 via JWKS (JWT_JWKS_URL, JWT_ISSUER, JWT_AUDIENCE)
          * or HS256 via JWT_HS256_SECRET
    """

    def __init__(self, app):
        super().__init__(app)
        self.s = get_settings()
        self._jwks_cache: dict[str, Any] = {}
        self._jwks_expiry: float = 0.0

    async def dispatch(self, request: Request, call_next):
        # Allow health/metrics without auth
        if request.url.path in ("/health", "/metrics"):
            return await call_next(request)

        if self.s.AUTH_MODE == "jwt":
            ok, err = await self._check_jwt(request)
            if not ok:
                return JSONResponse(
                    {"detail": f"Unauthorized: {err or 'invalid token'}"}, status_code=401
                )
        else:
            # API key mode
            key = request.headers.get("X-API-Key")
            if not key:
                auth = request.headers.get("Authorization", "")
                if auth.startswith("Bearer "):
                    key = auth.split(" ", 1)[1].strip()
            if not key or not self.s.API_KEY or key != self.s.API_KEY:
                return JSONResponse({"detail": "Unauthorized"}, status_code=401)

        return await call_next(request)

    async def _check_jwt(self, request: Request) -> tuple[bool, Optional[str]]:
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return False, "missing bearer token"
        token = auth.split(" ", 1)[1].strip()

        # HS256 path (simple shared secret)
        if self.s.JWT_HS256_SECRET:
            try:
                jwt.decode(
                    token,
                    self.s.JWT_HS256_SECRET,
                    algorithms=["HS256"],
                    audience=self.s.JWT_AUDIENCE,
                    issuer=self.s.JWT_ISSUER,
                    options={"require": ["exp"]},
                )
                return True, None
            except Exception as e:  # noqa: BLE001
                return False, str(e)

        # JWKS path (RS256)
        if not self.s.JWT_JWKS_URL:
            return False, "no JWKS or HS256 secret configured"

        try:
            jwks = await self._get_jwks()
            unverified = jwt.get_unverified_header(token)
            kid = unverified.get("kid")
            if not kid:
                return False, "no kid in header"

            key = next((k for k in jwks["keys"] if k.get("kid") == kid), None)
            if not key:
                return False, "kid not found in JWKS"

            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
            jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                audience=self.s.JWT_AUDIENCE,
                issuer=self.s.JWT_ISSUER,
                options={"require": ["exp"]},
            )
            return True, None
        except Exception as e:  # noqa: BLE001
            return False, str(e)

    async def _get_jwks(self) -> Dict[str, Any]:
        # Basic 5-minute cache
        now = time.time()
        if self._jwks_cache and now < self._jwks_expiry:
            return self._jwks_cache  # type: ignore[return-value]
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(self.s.JWT_JWKS_URL)  # type: ignore[arg-type]
            resp.raise_for_status()
            data = resp.json()
            self._jwks_cache = data
            self._jwks_expiry = now + 300
            return data

