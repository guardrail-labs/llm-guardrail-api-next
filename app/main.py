from __future__ import annotations

from fastapi import FastAPI

# Core routes
try:  # pragma: no cover
    from app.routes.guardrail import router as guardrail_router  # legacy ingress
    from app.routes.guardrail import threat_admin_router
except Exception:  # pragma: no cover
    guardrail_router = None
    threat_admin_router = None

from app.routes.openai_compat import router as oai_router, azure_router
from app.routes.metrics_route import router as metrics_router


def _create_app() -> FastAPI:
    app = FastAPI(title="LLM Guardrail API", version="next")

    # Include OpenAI/Azure compatibility routes
    app.include_router(oai_router)
    app.include_router(azure_router)

    # Include legacy guardrail routes if available
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

