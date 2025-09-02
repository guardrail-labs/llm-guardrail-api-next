# app/main.py
from __future__ import annotations

import importlib
import uuid
from typing import TYPE_CHECKING, Optional, Type

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import get_settings
from app.middleware.access_log import AccessLogMiddleware
from app.middleware.request_id import RequestIDMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware

# Always-on routers
from app.routes.admin import router as admin_router
from app.routes.health import router as health_router
from app.routes.metrics_route import router as metrics_router
from app.routes.openai_compat import azure_router, router as oai_router
from app.routes.ready import router as ready_router
from app.telemetry.logging import configure_logging

# Optional middleware imports (mypy-safe pattern)
if TYPE_CHECKING:
    pass

RateLimitMW: Optional[Type[object]] = None
LatencyHistogramMW: Optional[Type[object]] = None
try:
    from app.middleware.rate_limit import RateLimitMiddleware as _RateLimitMiddleware

    RateLimitMW = _RateLimitMiddleware
except Exception:  # pragma: no cover
    RateLimitMW = None

try:
    from app.telemetry.latency import (
        LatencyHistogramMiddleware as _LatencyHistogramMiddleware,
    )

    LatencyHistogramMW = _LatencyHistogramMiddleware
except Exception:  # pragma: no cover
    LatencyHistogramMW = None


def _include_if_present(app: FastAPI, dotted: str, attr: str = "router") -> None:
    """
    Import module by dotted path if it exists at runtime and include its 'router'
    (or custom attr) if present. Uses importlib to keep mypy happy.
    """
    try:
        mod = importlib.import_module(dotted)
        r = getattr(mod, attr, None)
        if r is not None:
            app.include_router(r)
    except Exception:
        # Silently ignore missing/failed optional modules
        pass


def create_app() -> FastAPI:
    s = get_settings()
    configure_logging()

    app = FastAPI(title=s.APP_NAME)

    # CORS (handle wildcard + credentials constraint)
    origins_raw = (s.CORS_ALLOW_ORIGINS or "").strip()
    origins = [o.strip() for o in origins_raw.split(",") if o.strip()]
    if origins:
        allow_credentials = True
        if origins == ["*"]:
            # Starlette constraint: cannot combine "*" with allow_credentials=True
            allow_credentials = False
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=allow_credentials,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # Request ID first so every response gets X-Request-ID
    app.add_middleware(RequestIDMiddleware)

    # Access logging early to capture everything
    app.add_middleware(AccessLogMiddleware)

    # Security headers
    app.add_middleware(SecurityHeadersMiddleware)

    # Optional latency histogram
    if LatencyHistogramMW is not None and getattr(s, "ENABLE_LATENCY_HISTOGRAM", True):
        app.add_middleware(LatencyHistogramMW)  # type: ignore[arg-type]

    # Rate limiter: always add if available; it handles enabled vs headers-only itself
    try:
        from app.middleware.rate_limit import RateLimitMiddleware as _LocalRateLimitMW

        app.add_middleware(_LocalRateLimitMW)
    except Exception:
        if RateLimitMW is not None:
            app.add_middleware(RateLimitMW)  # type: ignore[arg-type]

    # Core routers
    app.include_router(health_router)
    app.include_router(ready_router)
    app.include_router(admin_router)

    # Threat admin router (optional)
    _include_if_present(app, "app.routes.admin_threat")
    # Compliance admin router (optional)
    _include_if_present(app, "app.routes.admin_compliance")

    app.include_router(metrics_router)
    app.include_router(oai_router)
    app.include_router(azure_router)

    # Feature routers (optional)
    _include_if_present(app, "app.routes.guardrail")
    _include_if_present(app, "app.routes.batch")
    _include_if_present(app, "app.routes.output")
    _include_if_present(app, "app.routes.proxy")

    # Error handlers (also set X-Request-ID, though RequestIDMiddleware already does)
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        rid = (
            getattr(request.state, "request_id", None)
            or request.headers.get("X-Request-ID")
            or str(uuid.uuid4())
        )
        return JSONResponse(
            status_code=exc.status_code,
            headers={"X-Request-ID": rid},
            content={
                "code": "not_found" if exc.status_code == 404 else "error",
                "detail": exc.detail,
                "request_id": rid,
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        rid = (
            getattr(request.state, "request_id", None)
            or request.headers.get("X-Request-ID")
            or str(uuid.uuid4())
        )
        return JSONResponse(
            status_code=500,
            headers={"X-Request-ID": rid},
            content={
                "code": "internal_error",
                "detail": "internal error",
                "request_id": rid,
            },
        )

    return app


# Tests import `build_app` from app.main
build_app = create_app

# Module-level app instance (also used by uvicorn)
app = create_app()
