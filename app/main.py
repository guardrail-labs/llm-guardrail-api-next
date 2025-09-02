from __future__ import annotations

import os
import uuid
from typing import Optional, TYPE_CHECKING

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException

# Routers (keep imports at top for E402)
from app.routes.metrics_route import router as metrics_router
from app.routes.openai_compat import azure_router, router as oai_router

if TYPE_CHECKING:
    from fastapi import APIRouter


# -----------------------------
# Middleware: request-id + security headers
# -----------------------------
class _RequestIdAndSecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        # Attach request_id to state for handlers/exception handlers
        request.state.request_id = rid

        resp = await call_next(request)

        # Ensure the header is present on every response
        resp.headers.setdefault("X-Request-ID", rid)
        # Basic security headers (tests check presence)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("X-XSS-Protection", "0")
        return resp


# -----------------------------
# Optional routers (import if present)
# -----------------------------
guardrail_router: Optional["APIRouter"] = None
threat_admin_router: Optional["APIRouter"] = None
try:  # pragma: no cover
    from app.routes.guardrail import router as _guardrail_router
    from app.routes.guardrail import threat_admin_router as _threat_admin_router

    guardrail_router = _guardrail_router
    threat_admin_router = _threat_admin_router
except Exception:  # pragma: no cover
    pass

health_router: Optional["APIRouter"] = None
try:  # pragma: no cover
    from app.routes.health import router as _health_router

    health_router = _health_router
except Exception:  # pragma: no cover
    pass

proxy_router: Optional["APIRouter"] = None
try:  # pragma: no cover
    from app.routes.proxy import router as _proxy_router

    proxy_router = _proxy_router
except Exception:  # pragma: no cover
    pass

batch_router: Optional["APIRouter"] = None
try:  # pragma: no cover
    from app.routes.batch import router as _batch_router

    batch_router = _batch_router
except Exception:  # pragma: no cover
    pass

output_router: Optional["APIRouter"] = None
try:  # pragma: no cover
    from app.routes.output import router as _output_router

    output_router = _output_router
except Exception:  # pragma: no cover
    pass

admin_router: Optional["APIRouter"] = None
try:  # pragma: no cover
    from app.routes.admin import router as _admin_router

    admin_router = _admin_router
except Exception:  # pragma: no cover
    pass


def _create_app() -> FastAPI:
    app = FastAPI(title="LLM Guardrail API", version="next")

    # --- Middleware ---
    app.add_middleware(_RequestIdAndSecurityMiddleware)

    # CORS (optional via env)
    allow_origins = (os.environ.get("CORS_ALLOW_ORIGINS") or "").strip()
    if allow_origins:
        origins = [o.strip() for o in allow_origins.split(",") if o.strip()]
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # Try to install the project’s rate-limit middleware (if it exists)
    # Use dynamic import to avoid mypy attr checks.
    try:  # pragma: no cover
        import importlib

        rl_mod = importlib.import_module("app.services.rate_limit")
        RateLimitMiddleware = getattr(rl_mod, "RateLimitMiddleware", None)
        if RateLimitMiddleware is not None:
            app.add_middleware(RateLimitMiddleware)
    except Exception:
        # If not present, continue gracefully; guardrail routes still have internal checks.
        pass

    # --- Exception handlers (404/500 JSON contract) ---
    @app.exception_handler(StarletteHTTPException)
    async def _http_exc_handler(request: Request, exc: StarletteHTTPException):
        # Let non-404 errors fall back to default behavior
        if exc.status_code != 404:
            return JSONResponse(
                status_code=exc.status_code,
                content={"detail": exc.detail},
                headers={"X-Request-ID": getattr(request.state, "request_id", "")},
            )
        rid = getattr(request.state, "request_id", "")
        body = {"code": "not_found", "detail": "not found", "request_id": rid}
        return JSONResponse(status_code=404, content=body, headers={"X-Request-ID": rid})

    @app.exception_handler(Exception)
    async def _unhandled_exc_handler(request: Request, exc: Exception):
        rid = getattr(request.state, "request_id", "")
        body = {"code": "internal_error", "detail": "internal error", "request_id": rid}
        return JSONResponse(status_code=500, content=body, headers={"X-Request-ID": rid})

    # --- Routers: OpenAI/Azure first (public API) ---
    app.include_router(oai_router)
    app.include_router(azure_router)

    # --- Optional routers (include when available) ---
    if health_router is not None:
        app.include_router(health_router)
    if proxy_router is not None:
        app.include_router(proxy_router)
    if batch_router is not None:
        app.include_router(batch_router)
    if output_router is not None:
        app.include_router(output_router)

    if guardrail_router is not None:
        app.include_router(guardrail_router)
    if threat_admin_router is not None:
        app.include_router(threat_admin_router)
    if admin_router is not None:
        app.include_router(admin_router)

    # --- Prometheus /metrics ---
    app.include_router(metrics_router)

    return app


def build_app() -> FastAPI:  # pragma: no cover - convenience for tests
    return _create_app()


def create_app() -> FastAPI:  # backwards compatibility alias
    return _create_app()


app = _create_app()
