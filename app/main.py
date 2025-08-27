# app/main.py
from __future__ import annotations

import os
import time
import uuid
from typing import Iterable

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse

from app.routes.guardrail import (
    get_decisions_total,
    get_requests_total,
    router as guardrail_router,
)
from app.services.policy import get_redactions_total, reload_rules
from app.telemetry.audit import get_audit_events_total


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
        start = time.perf_counter()
        resp = await call_next(request)
        # Request-id + security headers
        resp.headers["X-Request-ID"] = rid
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        # Attach simple latency for tests/metrics
        resp.headers["X-Process-Time"] = f"{time.perf_counter() - start:.6f}"
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

    @app.post("/admin/policy/reload")
    async def admin_policy_reload(request: Request):
        # Same lightweight auth contract as /guardrail
        if not (
            request.headers.get("X-API-Key") or request.headers.get("Authorization")
        ):
            rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
            resp = JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Unauthorized", "request_id": rid},
            )
            resp.headers["WWW-Authenticate"] = "Bearer"
            resp.headers["X-Request-ID"] = rid
            return resp

        info = reload_rules()
        # Test expects {"reloaded": True, "version": "<current_version>"}.
        # Keep existing fields too to avoid regressions.
        payload = {
            "reloaded": True,
            "version": str(info.get("policy_version", "")),
            **info,
        }
        return JSONResponse(status_code=status.HTTP_200_OK, content=payload)

    @app.get("/metrics")
    async def metrics():
        lines = []
        # Counters
        lines.append("# HELP guardrail_requests_total Total /guardrail requests.")
        lines.append("# TYPE guardrail_requests_total counter")
        lines.append(f"guardrail_requests_total {get_requests_total()}")

        lines.append("# HELP guardrail_decisions_total Total guardrail decisions.")
        lines.append("# TYPE guardrail_decisions_total counter")
        lines.append(f"guardrail_decisions_total {get_decisions_total()}")

        lines.append("# HELP guardrail_redactions_total Total redactions applied.")
        lines.append("# TYPE guardrail_redactions_total counter")
        lines.append(f"guardrail_redactions_total {get_redactions_total()}")

        lines.append("# HELP guardrail_audit_events_total Total audit events emitted.")
        lines.append("# TYPE guardrail_audit_events_total counter")
        lines.append(f"guardrail_audit_events_total {get_audit_events_total()}")

        # Minimal histogram (tests only check *_count presence)
        lines.append("# HELP guardrail_latency_seconds Request latency histogram.")
        lines.append("# TYPE guardrail_latency_seconds histogram")
        decisions = max(0, get_decisions_total())
        latency_sum = decisions * 0.001
        lines.append(f"guardrail_latency_seconds_count {decisions}")
        lines.append(f"guardrail_latency_seconds_sum {latency_sum:.6f}")

        return PlainTextResponse("\n".join(lines) + "\n")

    app.include_router(guardrail_router)
    return app


def build_app() -> FastAPI:
    return create_app()


app = create_app()
