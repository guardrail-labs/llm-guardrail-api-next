from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from app.models import (
    AdminReloadResponse,
    EvaluateRequest,
    EvaluateResponse,
    HealthResponse,
)

client = TestClient(app)


def test_health_contract_models():
    r = client.get("/health")
    assert r.status_code == 200
    parsed = HealthResponse.model_validate(r.json())
    assert parsed.ok is True
    assert parsed.status == "ok"


def test_evaluate_contract_models_and_redaction():
    req = EvaluateRequest(text="hello sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    r = client.post("/guardrail/evaluate", json=req.model_dump())
    assert r.status_code == 200
    parsed = EvaluateResponse.model_validate(r.json())
    assert parsed.action == "allow"
    assert "[REDACTED:" in parsed.transformed_text


def test_admin_reload_contract_model():
    r = client.post("/admin/policy/reload")
    assert r.status_code == 200
    parsed = AdminReloadResponse.model_validate(r.json())
    assert parsed.reloaded is True
