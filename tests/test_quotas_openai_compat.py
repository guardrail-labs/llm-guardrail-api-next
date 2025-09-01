from typing import Any, Dict

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.routes.openai_compat import router as oai_router, azure_router
from app.services import quotas


@pytest.fixture
def client_hard_quota() -> TestClient:
    quotas.reset_quota_state()
    app = FastAPI()
    # Per-app state overrides for quotas
    app.state.quota_enabled = True
    app.state.quota_mode = "hard"
    app.state.quota_per_minute = 1
    app.state.quota_per_day = 0
    app.include_router(oai_router)
    app.include_router(azure_router)
    return TestClient(app)


@pytest.fixture
def client_soft_quota() -> TestClient:
    quotas.reset_quota_state()
    app = FastAPI()
    app.state.quota_enabled = True
    app.state.quota_mode = "soft"
    app.state.quota_per_minute = 1
    app.state.quota_per_day = 0
    app.include_router(oai_router)
    app.include_router(azure_router)
    return TestClient(app)


def _completions(client: TestClient, text: str) -> int:
    resp = client.post(
        "/v1/completions",
        json={"model": "demo", "prompt": text, "stream": False},
    )
    return resp.status_code


def test_quota_hard_minute_429(client_hard_quota: TestClient) -> None:
    # first allowed
    assert _completions(client_hard_quota, "hello") == 200
    # second denied by hard cap
    resp = client_hard_quota.post(
        "/v1/completions",
        json={"model": "demo", "prompt": "again"},
    )
    assert resp.status_code == 429
    # guard + retry headers
    assert resp.headers["X-Guardrail-Policy-Version"]
    assert resp.headers["X-Guardrail-Ingress-Action"] == "deny"
    assert resp.headers["X-Guardrail-Egress-Action"] == "skipped"
    assert "Retry-After" in resp.headers


def test_quota_soft_minute_allows(client_soft_quota: TestClient) -> None:
    # soft cap should not block
    assert _completions(client_soft_quota, "one") == 200
    assert _completions(client_soft_quota, "two") == 200
