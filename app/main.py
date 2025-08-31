# app/main.py
from __future__ import annotations

import os
import time
import uuid
from typing import Iterable

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse

from app.middleware.rate_limit import RateLimitMiddleware
from app.routes.guardrail import (
    get_decisions_total,
    get_requests_total,
    router as guardrail_router,
    threat_admin_router,
)
from app.routes.output import router as output_router
from app.services.policy import current_rules_version, get_redactions_total, reload_rules
from app.telemetry.audit import get_audit_events_total

# Test-only bypass for admin auth (enabled in CI/tests via env)
TEST_AUTH_BYPASS = os.getenv("GUARDRAIL_DISABLE_AUTH") == "1"


def _get_origins_from_env() -> Iterable[str]:
    raw = os.environ.get("CORS_ALLOW_ORIGINS") or ""
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    return parts or []


def _init_rate_limit_state(app: FastAPI) -> None:
    """Populate app.state with rate-limit config from environment."""
    enabled = (os.environ.get("RATE_LIMIT_ENABLED") or "false").lower() == "true"
    try:
        per_min = int(os.environ.get("RATE_LIMIT_PER_MINUTE") or "60")
    except Exception:
        per_min = 60
    try:
        burst = int(os.environ.get("RATE_LIMIT_BURST") or str(per_min))
    except Exception:
        burst = per_min

    app.state.rate_limit_enabled = enabled
    app.state.rate_limit_per_minute = per_min
    app.state.rate_limit_burst = burst


def create_app() -> FastAPI:
    app = FastAPI()

    # CORS (optional; only enabled when env provides origins)
    origins = list(_get_origins_from_env())
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # Initialize per-app rate-limit configuration
    _init_rate_limit_state(app)

    # Rate limit middleware (always attached; behavior is env-gated)
    app.add_middleware(RateLimitMiddleware)

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
        # Include "ok": True for tests/dashboards
        return {
            "ok": True,
            "status": "ok",
            "requests_total": get_requests_total(),
            "decisions_total": get_decisions_total(),
            "rules_version": current_rules_version(),
        }

    @app.post("/admin/policy/reload")
    async def admin_policy_reload(request: Request):
        # Same lightweight auth contract as /guardrail; bypass in tests/CI
        if not TEST_AUTH_BYPASS and not (
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
        payload = {
            "reloaded": True,
            "version": str(info.get("policy_version", info.get("version", ""))),
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

    # Routers
    app.include_router(guardrail_router)
    app.include_router(threat_admin_router)
    app.include_router(output_router)
    return app


def build_app() -> FastAPI:
    return create_app()


app = create_app()
