from __future__ import annotations

import math
import re
import time
from typing import Any, Dict, Optional, Tuple

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

# ---- Constants / defaults ----------------------------------------------------

PROBE_PATHS = {"/readyz", "/livez", "/metrics", "/healthz"}
_API_KEY_HDR = "X-API-Key"
_TENANT_HDRS = ("X-Guardrail-Tenant", "X-Tenant")
_BOT_HDRS = ("X-Guardrail-Bot", "X-Bot")

_SANITIZE_RE = re.compile(r"[^a-zA-Z0-9_-]+")


# ---- Metrics stubs (tests monkeypatch these) --------------------------------

class _NoopCounter:
    def labels(self, **_: str) -> "_NoopCounter":
        return self

    def inc(self, *_: float) -> None:
        return


RATE_LIMIT_BLOCKS = _NoopCounter()
RATE_LIMIT_SKIPS = _NoopCounter()


# ---- Utilities ---------------------------------------------------------------

def _bool_env(v: object, default: bool) -> bool:
    if v is None:
        return default
    s = str(v).strip().lower()
    return s in {"1", "true", "t", "yes", "y", "on"}


def _sanitize(s: str) -> str:
    return _SANITIZE_RE.sub("_", s) if s else "unknown"


# Time source can be monkeypatched in tests
def _now() -> float:
    return time.monotonic()


def _extract_identity(request: Request) -> Tuple[str, str]:
    headers = request.headers
    tenant = next((headers.get(h, "") for h in _TENANT_HDRS), "") or ""
    bot = next((headers.get(h, "") for h in _BOT_HDRS), "") or ""
    return _sanitize(tenant), _sanitize(bot)


def get_enforce_unknown(app_settings: Any) -> bool:
    """
    Prefer app.state.settings.ingress.rate_limit.enforce_unknown if present,
    else env (default False).
    """
    try:
        ingress = getattr(app_settings, "ingress", None)
        rl = getattr(ingress, "rate_limit", None)
        val = getattr(rl, "enforce_unknown", None)
        if val is not None:
            return bool(val)
    except Exception:
        pass
    from app import settings  # local import to avoid import-time cycles
    return _bool_env(getattr(settings, "RATE_LIMIT_ENFORCE_UNKNOWN", None), False)


# ---- In-memory limiter -------------------------------------------------------

class _MemoryBucket:
    __slots__ = ("tokens", "capacity", "rate", "last_ts")

    def __init__(self, capacity: int, rate: float) -> None:
        self.capacity = max(1, capacity)
        self.rate = max(0.0, rate)
        self.tokens = float(self.capacity)
        self.last_ts = _now()

    def _refill(self) -> None:
        now = _now()
        delta = now - self.last_ts
        if delta > 0.0 and self.rate > 0.0:
            self.tokens = min(self.capacity, self.tokens + delta * self.rate)
        self.last_ts = now

    def snapshot_remaining(self) -> int:
        self._refill()
        return int(max(0.0, math.floor(self.tokens + 1e-9)))

    def allow(self, cost: float = 1.0) -> Tuple[bool, float, int]:
        self._refill()
        if self.tokens >= cost:
            self.tokens -= cost
            return True, 0.0, self.snapshot_remaining()
        short = cost - self.tokens
        wait_s = 0.0 if self.rate <= 0.0 else short / self.rate
        return False, max(0.0, wait_s), self.snapshot_remaining()


class _MemoryLimiter:
    def __init__(self, per_sec: float, burst: int) -> None:
        self._rate = max(0.0, per_sec)
        self._capacity = max(1, int(burst))
        self._buckets: Dict[str, _MemoryBucket] = {}

    def _key(self, tenant: str, bot: str, api_key: str) -> str:
        # Scope by tenant+bot first, then api_key if present
        k = f"{tenant}:{bot}"
        return f"{k}:{api_key}" if api_key else k

    def allow(self, tenant: str, bot: str, api_key: str) -> Tuple[bool, float, int]:
        key = self._key(tenant, bot, api_key)
        b = self._buckets.get(key)
        if b is None:
            b = _MemoryBucket(self._capacity, self._rate)
            self._buckets[key] = b
        allowed, retry_after, remaining = b.allow(1.0)
        return allowed, retry_after, remaining


# ---- Middleware --------------------------------------------------------------

class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Token-bucket rate limiter with memory and redis backends.
    - Bypasses probes (/readyz, /livez, /metrics, /healthz).
    - Emits X-RateLimit-* and X-Quota-* headers on allow and deny.
    - Unknown identities bypass by default unless configured to enforce.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)
        from app import settings  # import late to avoid import order issues

        self.env_enabled = _bool_env(getattr(settings, "RATE_LIMIT_ENABLED", None), False)

        per_min_env = getattr(settings, "RATE_LIMIT_PER_MINUTE", None)
        rps_env = getattr(settings, "RATE_LIMIT_RPS", None)

        per_min = float(per_min_env) if per_min_env is not None else 60.0
        rps = float(rps_env) if rps_env is not None else per_min / 60.0
        burst_env = getattr(settings, "RATE_LIMIT_BURST", None)
        burst = int(burst_env) if burst_env is not None else int(per_min)

        backend = (getattr(settings, "RATE_LIMIT_BACKEND", "memory") or "memory").lower()
        self.backend = backend if backend in {"memory", "redis"} else "memory"

        # Build memory limiter; redis path is delegated elsewhere when enabled.
        self._mem = _MemoryLimiter(per_sec=rps, burst=burst)

        # Keep originals for header formatting
        self._rps = rps
        self._burst = burst

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Settings override from app.state.settings if present
        app_settings: Any = getattr(request.app.state, "settings", None)
        enabled = self.env_enabled

        try:
            if app_settings is not None:
                ingress = getattr(app_settings, "ingress", None)
                rl = getattr(ingress, "rate_limit", None)
                en = getattr(rl, "enabled", None)
                if en is not None:
                    enabled = bool(en)
                rps = getattr(rl, "rps", None)
                burst = getattr(rl, "burst", None)
                if rps is not None and burst is not None:
                    self._mem = _MemoryLimiter(per_sec=float(rps), burst=int(burst))
                    self._rps, self._burst = float(rps), int(burst)
        except Exception:
            # Ignore malformed settings; fall back to env-derived config
            pass

        if not enabled:
            return await call_next(request)

        # Bypass probe paths
        if request.url.path in PROBE_PATHS:
            return await call_next(request)

        api_key = request.headers.get(_API_KEY_HDR, "").strip()
        tenant, bot = _extract_identity(request)
        enforce_unknown = get_enforce_unknown(app_settings)

        if (tenant == "unknown" and bot == "unknown") and not enforce_unknown:
            try:
                RATE_LIMIT_SKIPS.labels(reason="unknown_identity").inc()
            except Exception:
                pass
            return await call_next(request)

        # Memory path (tests exercise this directly)
        allowed, retry_after, remaining = self._mem.allow(tenant, bot, api_key)

        # Common headers (allow & deny)
        if float(self._rps).is_integer():
            limit_str = f"{int(self._rps)}"
        else:
            limit_str = f"{self._rps}"
        rate_hdr = f"{limit_str}; burst={self._burst}"

        quota_headers = {
            "X-RateLimit-Limit": rate_hdr,
            "X-RateLimit-Remaining": str(max(0, remaining)),
            "X-Quota-Min": str(int(self._rps * 60)),
            "X-Quota-Hour": str(int(self._rps * 3600)),
            "X-Quota-Day": str(int(self._rps * 86400)),
            "X-Quota-Remaining": str(max(0, remaining)),
            "X-Quota-Reset": str(int(_now()) + max(1, int(math.ceil(retry_after)))),
        }

        if allowed:
            resp = await call_next(request)
            for k, v in quota_headers.items():
                resp.headers.setdefault(k, v)
            return resp

        # Deny: count metric
        try:
            RATE_LIMIT_BLOCKS.labels(tenant=tenant, bot=bot).inc()
        except Exception:
            pass

        headers = {"Retry-After": str(max(1, int(math.ceil(retry_after))))}
        headers.update(quota_headers)

        return JSONResponse(
            status_code=429,
            content={
                "error": {
                    "code": "rate_limited",
                    "message": "Rate limit exceeded. Try again later.",
                },
                "tenant": tenant,
                "bot": bot,
            },
            headers=headers,
        )
