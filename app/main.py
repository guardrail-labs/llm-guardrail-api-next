from __future__ import annotations

import importlib
import os
import pkgutil
import time
from typing import Any, List, Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.routing import APIRouter
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response as StarletteResponse
from starlette.types import Message, Receive, Scope, Send

from app.metrics.route_label import route_label
from app.middleware.abuse_gate import AbuseGateMiddleware
from app.middleware.quota import QuotaMiddleware
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.request_id import RequestIDMiddleware, get_request_id
from app.telemetry.tracing import TracingMiddleware

# Prometheus (optional; tests expect metrics but we guard imports)
try:  # pragma: no cover
    from prometheus_client import REGISTRY as _PromRegistryObj, Histogram as _PromHistogramCls
    PromHistogram: Any | None = _PromHistogramCls
    PromRegistry: Any | None = _PromRegistryObj
except Exception:  # pragma: no cover
    PromHistogram = None
    PromRegistry = None


def _truthy(val: object) -> bool:
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


def _get_or_create_latency_histogram() -> Optional[Any]:
    """
    Create the guardrail_latency_seconds histogram exactly once per process.

    IMPORTANT: tests expect a single 'endpoint' label.
    """
    if PromHistogram is None or PromRegistry is None:  # pragma: no cover
        return None

    name = "guardrail_latency_seconds"

    # If already registered, reuse it.
    try:
        names_map = getattr(PromRegistry, "_names_to_collectors", None)
        if isinstance(names_map, dict):
            existing = names_map.get(name)
            if existing is not None:
                return existing
    except Exception:
        pass

    try:
        return _PromHistogramCls(name, "Request latency in seconds", ["endpoint"])
    except ValueError:
        # Another import path created it — fetch and reuse.
        try:
            names_map = getattr(PromRegistry, "_names_to_collectors", None)
            if isinstance(names_map, dict):
                return names_map.get(name)
        except Exception:
            return None
        return None


# ---- Error/401 helpers -------------------------------------------------------

_RATE_HEADERS = ("X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset")


def _safe_headers_copy(src_headers) -> dict[str, str]:
    out: dict[str, str] = {}

    # Prefer Starlette's raw header bytes if available
    raw = getattr(src_headers, "raw", None)
    if raw is not None:
        try:
            for k, v in raw:
                out.setdefault(k.decode("latin-1"), v.decode("latin-1"))
        except Exception:
            # fall through to items() path
            pass

    if not out:
        try:
            items = src_headers.items() if hasattr(src_headers, "items") else []
            for k, v in items:
                out.setdefault(str(k), str(v))
        except Exception:
            pass

    rid = out.get("X-Request-ID") or (get_request_id() or "")
    if rid:
        out["X-Request-ID"] = rid

    now = int(time.time())
    defaults = {
        "X-RateLimit-Limit": "60",
        "X-RateLimit-Remaining": "3600",
        "X-RateLimit-Reset": str(now + 60),
    }
    for k in _RATE_HEADERS:
        out.setdefault(k, defaults[k])

    return out


def _status_code_to_code(status: int) -> str:
    if status == 401:
        return "unauthorized"
    if status == 404:
        return "not_found"
    if status == 413:
        return "payload_too_large"
    if status == 429:
        return "rate_limited"
    return "internal_error"


def _json_error(detail: str, status: int, base_headers=None) -> JSONResponse:
    payload = {
        "code": _status_code_to_code(status),
        "detail": detail,
        "request_id": get_request_id() or "",
    }
    headers = _safe_headers_copy(base_headers or {})
    headers["X-Request-ID"] = payload["request_id"]
    return JSONResponse(payload, status_code=status, headers=headers)


def _include_all_route_modules(app: FastAPI) -> int:
    try:
        routes_pkg = importlib.import_module("app.routes")
    except Exception:
        return 0

    count = 0
    for m in pkgutil.iter_modules(routes_pkg.__path__, routes_pkg.__name__ + "."):
        try:
            mod = importlib.import_module(m.name)
        except Exception:
            continue
        for attr_name in dir(mod):
            obj = getattr(mod, attr_name)
            if isinstance(obj, APIRouter):
                app.include_router(obj)
                count += 1
    return count


def create_app() -> FastAPI:
    app = FastAPI(title="llm-guardrail-api")

    app.add_middleware(RequestIDMiddleware)

    if _truthy(os.getenv("OTEL_ENABLED", "false")):
        app.add_middleware(TracingMiddleware)

    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(QuotaMiddleware)
    app.add_middleware(AbuseGateMiddleware)

    raw_origins = (os.getenv("CORS_ALLOW_ORIGINS") or "*").split(",")
    origins: List[str] = [o.strip() for o in raw_origins if o.strip()]
    if origins:
        allow_credentials = True
        if origins == ["*"]:
            allow_credentials = False
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=allow_credentials,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    hist = _get_or_create_latency_histogram()

    @app.middleware("http")
    async def latency_histogram_middleware(request: StarletteRequest, call_next):
        start = time.perf_counter()
        try:
            response: StarletteResponse = await call_next(request)
            return response
        finally:
            if hist is not None:
                try:
                    dur = max(time.perf_counter() - start, 0.0)
                    safe_endpoint = route_label(request.url.path)
                    hist.labels(endpoint=safe_endpoint).observe(dur)
                except Exception:
                    pass

    @app.middleware("http")
    async def security_headers_middleware(request: StarletteRequest, call_next):
        resp: StarletteResponse = await call_next(request)
        h = resp.headers
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("X-Frame-Options", "DENY")
        h.setdefault("Referrer-Policy", "no-referrer")
        h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        h.setdefault("Permissions-Policy", "interest-cohort=()")
        return resp

    @app.middleware("http")
    async def normalize_unauthorized_middleware(request: StarletteRequest, call_next):
        resp: StarletteResponse = await call_next(request)
        if resp.status_code != 401:
            return resp
        payload = {
            "code": "unauthorized",
            "detail": "Unauthorized",
            "request_id": get_request_id() or "",
        }
        safe_headers = _safe_headers_copy(resp.headers)
        return JSONResponse(payload, status_code=401, headers=safe_headers)

    _include_all_route_modules(app)

    @app.get("/health")
    async def _health_fallback():
        return {"status": "ok", "ok": True}

    @app.exception_handler(StarletteHTTPException)
    async def _http_exc_handler(request: Request, exc: StarletteHTTPException):
        return _json_error(str(exc.detail), exc.status_code, base_headers=request.headers)

    @app.exception_handler(Exception)
    async def _internal_exc_handler(request: Request, exc: Exception):
        return _json_error("Internal Server Error", 500, base_headers=request.headers)

    return app


# -------------------- ASGI wrapper: SSE body prebuffer + safe disconnect ------

class _SSEReceiveShield:
    """
    For requests with 'Accept: text/event-stream', pre-drain/cache the entire
    request body from the *original* receive() before calling into the app.
    After the cached body is exhausted, *always* return 'http.disconnect' for
    any further receive() calls.

    This prevents Starlette's BaseHTTPMiddleware (_CachedRequest) from ever
    encountering a stray 'http.request' once the body has been consumed,
    fixing flaky 'Unexpected message received: http.request' errors during SSE.
    """

    def __init__(self, app: FastAPI) -> None:
        self._app = app

    def __getattr__(self, name: str) -> Any:  # pragma: no cover
        return getattr(self._app, name)

    def openapi(self) -> Any:  # pragma: no cover
        return self._app.openapi()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self._app(scope, receive, send)
            return

        # Detect SSE via Accept header
        def _is_sse() -> bool:
            try:
                for k, v in scope.get("headers") or []:
                    if k == b"accept" and b"text/event-stream" in v:
                        return True
            except Exception:
                pass
            return False

        if not _is_sse():
            await self._app(scope, receive, send)
            return

        # Pre-drain & cache the entire body from the original receive()
        cached: list[Message] = []

        while True:
            msg = await receive()
            mtype = msg.get("type")
            if mtype == "http.request":
                cached.append(msg)
                if not bool(msg.get("more_body", False)):
                    break  # EOF
                continue
                if mtype == "http.disconnect":
                    break
            # Any other message types are forwarded as part of the cache too.
            cached.append(msg)
            # If this wasn't a request-body, just continue draining until EOF or disconnect.

        # Serve cached body to the app, then switch to permanent disconnects
        idx = 0

        async def patched_receive() -> Message:
            nonlocal idx
            if idx < len(cached):
                m = cached[idx]
                idx += 1
                return m
            # After the app has consumed the cached body, never return another request message.
            return {"type": "http.disconnect"}

        await self._app(scope, patched_receive, send)


# Factory + exports ------------------------------------------------------------
build_app = create_app
_inner_app: FastAPI = create_app()
app = _SSEReceiveShield(_inner_app)
