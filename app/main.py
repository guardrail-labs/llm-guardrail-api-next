from __future__ import annotations

from typing import Optional, TYPE_CHECKING

from fastapi import FastAPI

# All imports at top (ruff E402 compliance)
from app.routes.metrics_route import router as metrics_router
from app.routes.openai_compat import azure_router, router as oai_router

if TYPE_CHECKING:
    from fastapi import APIRouter

# Optional legacy guardrail routes (present in some builds)
guardrail_router: Optional["APIRouter"] = None
threat_admin_router: Optional["APIRouter"] = None
try:  # pragma: no cover
    from app.routes.guardrail import router as _guardrail_router
    from app.routes.guardrail import threat_admin_router as _threat_admin_router

    guardrail_router = _guardrail_router
    threat_admin_router = _threat_admin_router
except Exception:  # pragma: no cover
    pass


def _create_app() -> FastAPI:
    app = FastAPI(title="LLM Guardrail API", version="next")

    # OpenAI/Azure compatibility routes
    app.include_router(oai_router)
    app.include_router(azure_router)

    # Legacy guardrail routes if available
    if guardrail_router is not None:
        app.include_router(guardrail_router)
    if threat_admin_router is not None:
        app.include_router(threat_admin_router)

    # Prometheus /metrics
    app.include_router(metrics_router)

    return app


def build_app() -> FastAPI:  # pragma: no cover - convenience for tests
    return _create_app()


def create_app() -> FastAPI:  # backwards compatibility alias
    return _create_app()


app = _create_app()
