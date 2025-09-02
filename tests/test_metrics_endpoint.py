from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.routes.openai_compat import router as oai_router
from app.routes.metrics_route import router as metrics_router


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(oai_router)
    app.include_router(metrics_router)
    return app


def test_metrics_contains_family_and_breakdowns() -> None:
    app = _build_app()
    client = TestClient(app)

    # Trigger at least one decision path
    resp = client.post(
        "/v1/completions",
        json={"model": "demo", "prompt": "hello", "stream": False},
        headers={"X-Tenant-ID": "default", "X-Bot-ID": "default"},
    )
    assert resp.status_code == 200

    m = client.get("/metrics")
    assert m.status_code == 200
    text = m.text

    # Global family totals exist
    assert 'guardrail_decisions_family_total{family="allow"}' in text

    # Tenant/bot breakdown exists (defaults)
    assert (
        'guardrail_decisions_family_bot_total{tenant="default",bot="default",'
        'family="allow"}' in text
    )

