from __future__ import annotations

import os
import uuid
from typing import Iterable

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse

from app.routes.guardrail import (
    router as guardrail_router,
    get_requests_total,
    get_decisions_total,
)
from app.services.policy import get_redactions_total


def _get_origins_from_env() -> Iterable[str]:
    raw = os.environ.get("CORS_ALLOW_ORIGINS") or ""
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    return parts or []


def create_app() -> FastAPI:
    app = FastAPI()

    origins = list(_get_origins_from_env())
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    @app.middleware("http")
    async def add_request_id_and_security_headers(request: Request, call_next):
        rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        resp = await call_next(request)
        resp.headers["X-Request-ID"] = rid
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    @app.exception_handler(404)
    async def not_found_handler(request: Request, exc):
        rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        resp = JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"code": "not_found", "request_id": rid},
        )
        resp.headers["X-Request-ID"] = rid
        return resp

    @app.exception_handler(500)
    async def internal_error_handler(request: Request, exc: Exception):
        rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        resp = JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"code": "internal_error", "request_id": rid},
        )
        resp.headers["X-Request-ID"] = rid
        return resp

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/metrics")
    async def metrics():
        lines = []
        lines.append("# HELP guardrail_requests_total Total /guardrail requests.")
        lines.append("# TYPE guardrail_requests_total counter")
        lines.append(f"guardrail_requests_total {get_requests_total()}")
        lines.append("# HELP guardrail_decisions_total Total guardrail decisions.")
        lines.append("# TYPE guardrail_decisions_total counter")
        lines.append(f"guardrail_decisions_total {get_decisions_total()}")
        lines.append("# HELP guardrail_redactions_total Total redactions applied.")
        lines.append("# TYPE guardrail_redactions_total counter")
        lines.append(f"guardrail_redactions_total {get_redactions_total()}")
        return PlainTextResponse("\n".join(lines) + "\n")

    app.include_router(guardrail_router)
    return app


def build_app() -> FastAPI:
    return create_app()


app = create_app()
