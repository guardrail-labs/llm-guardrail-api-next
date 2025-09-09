import importlib

from fastapi.testclient import TestClient

import app.services.verifier as v
from app.main import app  # adjust if your FastAPI app is created elsewhere


def test_scoreboard_ok(monkeypatch):
    # Ensure a deterministic provider list
    monkeypatch.setenv("VERIFIER_PROVIDERS", "local_rules")
    importlib.reload(v)

    c = TestClient(app)
    r = c.get("/internal/verifier/scoreboard")
    assert r.status_code == 200
    j = r.json()
    assert "providers" in j and isinstance(j["providers"], list)
    assert "router" in j and "effective_order" in j["router"]
    assert j["router"]["effective_order"]  # non-empty when providers configured


def test_scoreboard_header_guard(monkeypatch):
    monkeypatch.setenv("INTERNAL_AUTH", "topsecret")
    c = TestClient(app)
    r = c.get("/internal/verifier/scoreboard")
    assert r.status_code == 403

    r2 = c.get(
        "/internal/verifier/scoreboard", headers={"X-Internal-Auth": "topsecret"}
    )
    assert r2.status_code == 200
