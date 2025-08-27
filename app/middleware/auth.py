from __future__ import annotations

from fastapi import Request
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import get_settings

# Public endpoints (no API key required)
_PUBLIC_PATHS = {
    "/health",
    "/metrics",
    "/openapi.json",
    "/docs",
    "/docs/oauth2-redirect",
}
_PUBLIC_PREFIXES = ("/static/",)

# Only these prefixes require auth by default
_PROTECTED_PREFIXES = ("/guardrail", "/admin")


class APIKeyAuthMiddleware(BaseHTTPMiddleware):
    """
    Require an API key only for protected paths.
    Accepts either 'X-API-Key' or 'Authorization: Bearer <key>'.
    """

    def __init__(self, app) -> None:
        super().__init__(app)
        self.s = get_settings()

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Unprotected paths
        if path in _PUBLIC_PATHS or any(path.startswith(p) for p in _PUBLIC_PREFIXES):
            return await call_next(request)

        # Only protect selected prefixes
        if not path.startswith(_PROTECTED_PREFIXES):
            return await call_next(request)

        if not self._authorized(request):
            # Let the global error handler format the body
            raise StarletteHTTPException(status_code=401, detail="unauthorized")

        return await call_next(request)

    def _authorized(self, request: Request) -> bool:
        expected = getattr(self.s, "API_KEY", None)
        if not expected:
            return True  # No key configured -> auth disabled

        header_key = request.headers.get("X-API-Key")
        if header_key and header_key == expected:
            return True

        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth.split(" ", 1)[1].strip()
            if token == expected:
                return True

        return False
