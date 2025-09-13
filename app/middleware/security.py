# app/middleware/security.py
# Summary (PR-J: Auth + Rate Limit, opt-in):
# - Optional API key auth and in-memory token-bucket rate limiting.
# - Disabled by default; enable via env: API_SECURITY_ENABLED=1
# - Configure keys: GUARDRAIL_API_KEYS="key1,key2"
# - Configure scope: SECURED_PATH_PREFIXES (e.g., "/v1,/admin")
# - Rate limit: RATE_LIMIT_RPS (float), RATE_LIMIT_BURST (int)
# - Install by calling install_security(app) (wire from app/main.py).
#
# Update (mypy fixes):
# - Define our own RequestHandler type alias instead of importing
#   RequestResponseEndpoint (not present in older Starlette stubs).
# - Annotate call_next with RequestHandler so returns are typed as Response.
# - Guard request.client None case.

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Dict, List, Tuple

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

# Type alias for Starlette's request handler callback
RequestHandler = Callable[[Request], Awaitable[Response]]


# ----------------------------- config helpers ---------------------------------


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _float_env(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        val = float(raw.strip())
        if val != val or val < 0:  # NaN or negative
            return default
        return val
    except Exception:
        return default


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        val = int(float(raw.strip()))
        if val < 0:
            return default
        return val
    except Exception:
        return default


def _csv_env(name: str) -> List[str]:
    raw = os.getenv(name) or ""
    parts = [p.strip() for p in raw.replace(";", ",").replace(":", ",").split(",")]
    return [p for p in parts if p]


def security_enabled() -> bool:
    return _bool_env("API_SECURITY_ENABLED", False)


def api_keys() -> Tuple[str, ...]:
    keys = tuple(_csv_env("GUARDRAIL_API_KEYS"))
    return keys


def secured_prefixes() -> Tuple[str, ...]:
    parts = tuple(_csv_env("SECURED_PATH_PREFIXES")) or ("/v1",)
    return parts


def rate_limit_config() -> Tuple[float, int]:
    rps = _float_env("RATE_LIMIT_RPS", 0.0)  # 0 disables limiting
    burst = _int_env("RATE_LIMIT_BURST", 0)
    return rps, burst


# ------------------------------- token bucket ---------------------------------


@dataclass
class _Bucket:
    capacity: float
    tokens: float
    rps: float
    last_ts: float

    def take(self, n: float, now: float) -> bool:
        elapsed = max(0.0, now - self.last_ts)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rps)
        self.last_ts = now
        if self.tokens >= n:
            self.tokens -= n
            return True
        return False


class _Limiter:
    def __init__(self, rps: float, burst: int) -> None:
        self._rps = rps
        self._burst = burst
        self._buckets: Dict[Tuple[str, str], _Bucket] = {}

    def allow(self, key: str, path: str, now: float) -> bool:
        k = (key, path)
        b = self._buckets.get(k)
        if b is None:
            b = _Bucket(
                capacity=max(1.0, float(self._burst)),
                tokens=float(self._burst) if self._burst > 0 else 1.0,
                rps=max(0.0, self._rps),
                last_ts=now,
            )
            self._buckets[k] = b
        return b.take(1.0, now)


# --------------------------------- middlewares --------------------------------


class APIKeyAuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, keys: Tuple[str, ...], prefixes: Tuple[str, ...]) -> None:
        super().__init__(app)
        self._keys = set(keys)
        self._prefixes = prefixes
        self._explicit = bool(_csv_env("SECURED_PATH_PREFIXES"))

    async def dispatch(self, request: Request, call_next: RequestHandler) -> Response:
        path = request.url.path or "/"
        if not self._path_secured(path):
            return await call_next(request)

        key = request.headers.get("x-api-key") or request.query_params.get("api_key")
        if not key or key not in self._keys:
            return JSONResponse({"detail": "Unauthorized"}, status_code=401)
        return await call_next(request)

    def _path_secured(self, path: str) -> bool:
        if not self._prefixes:
            return False
        if not any(path.startswith(p) for p in self._prefixes):
            return False
        if self._explicit:
            return True
        # Default exemptions when using default '/v1' only
        for ex in ("/admin", "/metrics", "/health", "/healthz", "/docs", "/openapi.json"):
            if path.startswith(ex):
                return False
        return True


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, rps: float, burst: int, prefixes: Tuple[str, ...]) -> None:
        super().__init__(app)
        self._rps = rps
        self._burst = burst
        self._prefixes = prefixes
        self._limiter = _Limiter(rps, burst)

    async def dispatch(self, request: Request, call_next: RequestHandler) -> Response:
        if self._rps <= 0.0:
            return await call_next(request)

        path = request.url.path or "/"
        if not any(path.startswith(p) for p in self._prefixes):
            return await call_next(request)

        principal = request.headers.get("x-api-key")
        if not principal:
            client = request.client
            principal = client.host if (client is not None and client.host) else "anon"

        now = time.monotonic()
        if not self._limiter.allow(principal, path, now):
            return JSONResponse({"detail": "Too Many Requests"}, status_code=429)
        return await call_next(request)


# ------------------------------- installer ------------------------------------


def install_security(app) -> None:
    """Attach security middlewares if API_SECURITY_ENABLED=1."""
    if not security_enabled():
        return
    keys = api_keys()
    prefixes = secured_prefixes()
    rps, burst = rate_limit_config()
    app.add_middleware(APIKeyAuthMiddleware, keys=keys, prefixes=prefixes)
    app.add_middleware(RateLimitMiddleware, rps=rps, burst=burst, prefixes=prefixes)
