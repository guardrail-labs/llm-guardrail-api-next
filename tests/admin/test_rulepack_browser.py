from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app())


def test_rulepacks_index_and_detail(client, monkeypatch):
    monkeypatch.setenv("GUARDRAIL_DISABLE_AUTH", "1")

    idx = client.get("/admin/rulepacks")
    assert idx.status_code == 200
    j = idx.json()
    assert "available" in j and "hipaa" in j["available"] and "gdpr" in j["available"]

    hipaa = client.get("/admin/rulepacks/hipaa")
    assert hipaa.status_code == 200
    assert hipaa.json().get("name") in ("HIPAA", "Hipaa", "hipaa")
