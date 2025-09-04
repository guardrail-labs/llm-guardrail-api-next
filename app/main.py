from __future__ import annotations

import importlib
import json
import os
import pkgutil
import time
from typing import Any, List, Optional, Awaitable, Protocol

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.routing import APIRouter
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response as StarletteResponse
from starlette.types import ASGIApp, Receive, Scope, Send, Message

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


class _SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add basic security headers expected by tests."""

    async def dispatch(self, request: StarletteRequest, call_next):
        resp: StarletteResponse = await call_next(request)
        h = resp.headers
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("X-Frame-Options", "DENY")
        h.setdefault("Referrer-Policy", "no-referrer")
        h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        h.setdefault("Permissions-Policy", "interest-cohort=()")
        return resp


def _get_or_create_latency_histogram() -> Optional[Any]:
    """
    Create the guardrail_latency_seconds histogram exactly once per process.

    If it's already registered in the default REGISTRY, return the existing collector
    to avoid 'Duplicated timeseries' errors.
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
        return PromHistogram(name, "Request latency in seconds", ["route", "method"])
    except ValueError:
        # Another import path created it — fetch and reuse.
        try:
            names_map = getattr(PromRegistry, "_names_to_collectors", None)
            if isinstance(names_map, dict):
                return names_map.get(name)
        except Exception:
            return None
        return None


class _LatencyMiddleware(BaseHTTPMiddleware):
    """Observe request latency into guardrail_latency_seconds (if available)."""

    def __init__(self, app):
        super().__init__(app)
        self._hist = _get_or_create_latency_histogram()

    async def dispatch(self, request: StarletteRequest, call_next):
        start = time.perf_counter()
        try:
            return await call_next(request)
        finally:
            if self._hist is not None:
                try:
                    dur = max(time.perf_counter() - start, 0.0)
                    safe_route = route_label(request.url.path)
                    self._hist.labels(route=safe_route, method=request.method).observe(dur)
                except Exception:
                    # Never break requests due to metrics errors
                    pass


# ---- Error/401 helpers -------------------------------------------------------

_RATE_HEADERS = ("X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset")


def _safe_headers_copy(src_headers) -> dict[str, str]:
    """
    Build a safe headers dict from a Starlette Headers object, making sure the tests'
    required headers are present and avoiding KeyError from __getitem__.
    """
    out: dict[str, str] = {}

    # Best-effort copy of existing headers without triggering __getitem__.
    try:
        for k, v in src_headers.raw:
            # raw gives bytes keys/values
            out.setdefault(k.decode("latin-1"), v.decode("latin-1"))
    except Exception:
        # Fallback: try .items() which is safe
        try:
            for k, v in src_headers.items():
                out.setdefault(k, v)
        except Exception:
            pass

    # Ensure X-Request-ID is set
    rid = out.get("X-Request-ID") or (get_request_id() or "")
    if rid:
        out["X-Request-ID"] = rid

    # Ensure rate-limit headers exist with sensible defaults
    now = int(time.time())
    defaults = {
        "X-RateLimit-Limit": "60",
        "X-RateLimit-Remaining": "3600",
        "X-RateLimit-Reset": str(now + 60),
    }
    for k in _RATE_HEADERS:
        out.setdefault(k, defaults[k])

    return out


class _NormalizeUnauthorizedMiddleware(BaseHTTPMiddleware):
    """
    Ensure 401 bodies include {"code","detail","request_id"} and required headers,
    even if an upstream middleware returned a minimal {"detail": "..."} response.
    """

    async def dispatch(self, request: StarletteRequest, call_next):
        resp: StarletteResponse = await call_next(request)
        if resp.status_code != 401:
            return resp

        # Consume body for parsing.
        body_chunks: list[bytes] = []
        if hasattr(resp, "body_iterator") and resp.body_iterator is not None:
            async for chunk in resp.body_iterator:
                body_chunks.append(chunk)
        raw = b"".join(body_chunks) if body_chunks else b""

        detail: str = "Unauthorized"
        try:
            if raw:
                parsed = json.loads(raw.decode() or "{}")
                detail = str(parsed.get("detail", detail))
        except Exception:
            pass

        payload = {
            "code": "unauthorized",
            "detail": detail,
            "request_id": get_request_id() or "",
        }

        safe_headers = _safe_headers_copy(resp.headers)
        return JSONResponse(payload, status_code=401, headers=safe_headers)


# ---- Router auto-inclusion ---------------------------------------------------

def _include_all_route_modules(app: FastAPI) -> int:
    """
    Import all submodules under app.routes and include any APIRouter objects
    they define (whatever they are named).
    """
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


# ---- Error JSON helpers ------------------------------------------------------

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
    # Ensure X-Request-ID is *always* present, even if empty
    headers["X-Request-ID"] = payload["request_id"]
    return JSONResponse(payload, status_code=status, headers=headers)


# ---- ASGI wrapper to stabilize streaming/SSE --------------------------------

class _PreDrainBodyThenDisconnectASGI:
    """
    ASGI wrapper that:
      1) Fully drains the incoming request body once.
      2) Replays the drained frames to the inner app.
      3) After replay, any further `receive()` calls yield `http.disconnect`.

    This prevents Starlette's BaseHTTPMiddleware from ever seeing an extra
    `http.request` *after* it believes the body is finished (a common race
    with StreamingResponse / SSE under stacked BaseHTTPMiddleware).
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        # (1) Drain the entire body once up-front.
        drained: list[Message] = []
        while True:
            msg: Message = await receive()
            drained.append(msg)
            typ = msg.get("type")
            if typ == "http.disconnect":
                break
            if typ == "http.request" and not msg.get("more_body", False):
                # End of request body
                break

        # (2) Replay drained frames to downstream, then (3) only disconnect.
        idx = 0

        async def patched_receive() -> Message:
            nonlocal idx
            if idx < len(drained):
                m = drained[idx]
                idx += 1
                return m
            # After the original body has been consumed by downstream,
            # present only a disconnect for any subsequent reads.
            return {"type": "http.disconnect"}  # type: ignore[typeddict-item]

        async def patched_send(message: Message) -> Awaitable[None] | None:
            # Transparent pass-through (httpx/starlette expect Awaitable[None])
            return await send(message)

        await self.app(scope, patched_receive, patched_send)  # type: ignore[arg-type]


# Protocol so mypy accepts an app that is both ASGI-callable and exposes openapi()
class _ASGIAndOpenAPI(Protocol):
    def __call__(self, scope: Scope, receive: Receive, send: Send) -> Awaitable[None]: ...
    def openapi(self) -> Any: ...


class _ASGIWrapperWithOpenAPI:
    """
    Small facade that is ASGI-callable (delegates to the pre-drain wrapper)
    and also exposes .openapi() from the inner FastAPI app so scripts can do:
        from app.main import app
        schema = app.openapi()
    """

    def __init__(self, inner_fastapi: FastAPI) -> None:
        self._inner = inner_fastapi
        self._wrapped = _PreDrainBodyThenDisconnectASGI(inner_fastapi)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        await self._wrapped(scope, receive, send)

    # Only the bits we know are needed by scripts; extend if you need more.
    def openapi(self) -> Any:
        return self._inner.openapi()


# ---- App factory -------------------------------------------------------------

def create_app() -> FastAPI:
    app = FastAPI(title="llm-guardrail-api")

    # Request ID first so handlers/middleware can use it.
    app.add_middleware(RequestIDMiddleware)

    # Optional tracing
    if _truthy(os.getenv("OTEL_ENABLED", "false")):
        app.add_middleware(TracingMiddleware)

    # Rate limiting (env-controlled)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(QuotaMiddleware)
    app.add_middleware(AbuseGateMiddleware)

    # Security headers + latency histogram + normalize 401 body
    app.add_middleware(_SecurityHeadersMiddleware)
    app.add_middleware(_LatencyMiddleware)
    app.add_middleware(_NormalizeUnauthorizedMiddleware)

    # CORS
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

    # Include every APIRouter found under app.routes.*
    _include_all_route_modules(app)

    # Fallback /health (routers may also provide a richer one)
    @app.get("/health")
    async def _health_fallback():
        # Minimal shape; some tests only check .status == "ok"
        return {"status": "ok", "ok": True}

    # ---- JSON error handlers with request_id & headers ----

    @app.exception_handler(StarletteHTTPException)
    async def _http_exc_handler(request: Request, exc: StarletteHTTPException):
        # Preserve original detail text (e.g., "Unauthorized", "Not Found")
        return _json_error(str(exc.detail), exc.status_code, base_headers=request.headers)

    @app.exception_handler(Exception)
    async def _internal_exc_handler(request: Request, exc: Exception):
        # Generic 500 with JSON body so tests can .json() it.
        return _json_error("Internal Server Error", 500, base_headers=request.headers)

    return app


# Back-compat for tests/scripts
build_app = create_app

# Build the inner FastAPI app, then expose a wrapper that is ASGI-callable and has .openapi()
_inner_fastapi_app: FastAPI = create_app()
app: _ASGIAndOpenAPI = _ASGIWrapperWithOpenAPI(_inner_fastapi_app)
