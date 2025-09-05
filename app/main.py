from __future__ import annotations

import asyncio
import importlib
import os
import pkgutil
import time
from typing import Any, Dict, List, Optional

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

# Optional Prometheus imports (guarded so tests don't fail if missing)
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
    Create/return the singleton guardrail_latency_seconds histogram with a single 'endpoint' label.
    """
    if PromHistogram is None or PromRegistry is None:  # pragma: no cover
        return None

    name = "guardrail_latency_seconds"
    # Reuse if already registered
    try:
        names_map = getattr(PromRegistry, "_names_to_collectors", None)
        if isinstance(names_map, dict) and name in names_map:
            return names_map[name]
    except Exception:
        pass

    try:
        return _PromHistogramCls(name, "Request latency in seconds", ["endpoint"])
    except ValueError:
        try:
            names_map = getattr(PromRegistry, "_names_to_collectors", None)
            if isinstance(names_map, dict):
                return names_map.get(name)
        except Exception:
            return None
        return None


_RATE_HEADERS = ("X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset")


def _safe_headers_copy(src_headers) -> Dict[str, str]:
    out: Dict[str, str] = {}

    raw = getattr(src_headers, "raw", None)
    if raw is not None:
        try:
            for k, v in raw:
                out.setdefault(k.decode("latin-1"), v.decode("latin-1"))
        except Exception:
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
    """
    Auto-include all APIRouter instances from app.routes.*
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


def create_app() -> FastAPI:
    app = FastAPI(title="llm-guardrail-api")

    # Middleware order matters; keep RequestID first so later layers can use it.
    app.add_middleware(RequestIDMiddleware)

    if _truthy(os.getenv("OTEL_ENABLED", "false")):
        app.add_middleware(TracingMiddleware)

    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(QuotaMiddleware)
    app.add_middleware(AbuseGateMiddleware)

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


# -------------------- ASGI wrapper: SSE shield (owner-task body delivery) -----

class _SSEShield:
    """
    Shield SSE endpoints from Starlette's background disconnect listener receiving
    stray 'http.request' frames.

    Strategy:
      1) Detect SSE via 'Accept: text/event-stream'.
      2) Fully pre-drain the original request body (aggregate bytes).
      3) Patch 'receive' so that:
         - Only the *owner task* (the task running this ASGI app call) ever
           receives a single aggregated 'http.request' frame.
         - All *other tasks* (e.g., Starlette's listen_for_disconnect task)
           always receive 'http.disconnect'.
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

        # SSE detection
        headers = scope.get("headers") or []
        is_sse = any(k == b"accept" and b"text/event-stream" in v.lower() for k, v in headers)
        if not is_sse:
            await self._app(scope, receive, send)
            return

        # 1) Pre-drain request body entirely.
        chunks: list[bytes] = []
        while True:
            msg = await receive()
            t = msg.get("type")
            if t == "http.request":
                body = msg.get("body", b"")
                if body:
                    chunks.append(body)
                if not msg.get("more_body", False):
                    break
            elif t == "http.disconnect":
                break
            else:
                # Ignore anything else (shouldn't happen in http scope)
                continue

        aggregated = b"".join(chunks)

        # 2) Owner task is the task executing this __call__
        owner_task = asyncio.current_task()
        served_once = False

        async def patched_receive() -> Message:
            nonlocal served_once
            # Only the owner task gets the one body frame; everyone else always sees a disconnect.
            if asyncio.current_task() is owner_task:
                if not served_once:
                    served_once = True
                    return {"type": "http.request", "body": aggregated, "more_body": False}
                return {"type": "http.disconnect"}
            # Non-owner tasks (e.g., Starlette's disconnect watcher)
            return {"type": "http.disconnect"}

        await self._app(scope, patched_receive, send)


# Factory + exports ------------------------------------------------------------
build_app = create_app
_inner_app: FastAPI = create_app()
app = _SSEShield(_inner_app)
