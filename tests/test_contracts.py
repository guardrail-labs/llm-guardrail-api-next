from __future__ import annotations

import os

from fastapi.testclient import TestClient

from app.main import app
from app.models import (
    AdminReloadResponse,
    EvaluateRequest,
    EvaluateResponse,
    HealthResponse,
)

os.environ["ADMIN_TOKEN"] = "test-token"
client = TestClient(app)
ADMIN_H = {"Authorization": "Bearer test-token"}


def test_health_contract_models():
    r = client.get("/health")
    assert r.status_code == 200
    parsed = HealthResponse.model_validate(r.json())
    assert parsed.ok is True
    assert parsed.status == "ok"
    assert {
        "policy",
        "decisions",
        "webhooks",
        "ratelimit",
        "metrics",
    }.issubset(parsed.checks.keys())


def test_evaluate_contract_models_and_redaction():
    req = EvaluateRequest(text="hello sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    r = client.post("/guardrail/evaluate", json=req.model_dump())
    assert r.status_code == 200
    parsed = EvaluateResponse.model_validate(r.json())
    assert parsed.action == "allow"
    assert "[REDACTED:" in parsed.transformed_text


def test_admin_reload_contract_model():
    r = client.post("/admin/policy/reload", headers=ADMIN_H)
    assert r.status_code == 200
    parsed = AdminReloadResponse.model_validate(r.json())
    assert parsed.ok is True
