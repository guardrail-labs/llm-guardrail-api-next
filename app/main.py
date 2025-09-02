from __future__ import annotations

import os
from typing import List

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.middleware.request_id import RequestIDMiddleware
from app.middleware.rate_limit import RateLimitMiddleware
from app.telemetry.tracing import TracingMiddleware

# Routers (must exist in your repo; tests import app.main.app/build_app/create_app)
from app.routes import guardrail as _guardrail
from app.routes import output as _output
from app.routes import batch as _batch
from app.routes import proxy as _proxy
from app.routes import openai_compat as _openai
from app.routes import admin_threat as _admin_threat


def _truthy(val: object) -> bool:
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


def create_app() -> FastAPI:
    app = FastAPI(title="llm-guardrail-api")

    # --- Middlewares: request id first so every response gets X-Request-ID ---
    app.add_middleware(RequestIDMiddleware)

    # Tracing (optional via env)
    if _truthy(os.getenv("OTEL_ENABLED", "false")):
        app.add_middleware(TracingMiddleware)

    # Rate limit (behavior controlled by env in middleware)
    app.add_middleware(RateLimitMiddleware)

    # CORS
    raw_origins = (os.getenv("CORS_ALLOW_ORIGINS") or "*").split(",")
    origins: List[str] = [o.strip() for o in raw_origins if o.strip()]
    if origins:
        allow_credentials = True
        if origins == ["*"]:
            # Starlette constraint: "*" cannot be combined with allow_credentials=True
            allow_credentials = False
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=allow_credentials,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # --- Routers ---
    app.include_router(_guardrail.router, prefix="/guardrail", tags=["guardrail"])
    app.include_router(_output.router, prefix="/guardrail", tags=["output"])
    app.include_router(_batch.router, prefix="/guardrail", tags=["batch"])
    app.include_router(_proxy.router, prefix="/proxy", tags=["proxy"])
    app.include_router(_openai.router, prefix="/v1", tags=["openai-compat"])
    app.include_router(_admin_threat.router, prefix="/admin/threat", tags=["admin"])

    # Health
    @app.get("/health")
    async def health():
        return {"ok": True}

    return app


# Keep tests and external scripts happy:
build_app = create_app
app = create_app()
