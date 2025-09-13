from fastapi.testclient import TestClient

from app.main import app  # assumes app is wired with guardrail routes

client = TestClient(app)


def _post_guardrail(text: str):
    return client.post("/guardrail/evaluate", json={"text": text})


def test_latency_budget_env_invalid_string_does_not_crash(monkeypatch):
    monkeypatch.setenv("VERIFIER_LATENCY_BUDGET_MS", "200ms")
    r = _post_guardrail("hello")
    assert r.status_code == 200
    body = r.json()
    assert "request_id" in body


def test_latency_budget_env_decimal_ok(monkeypatch):
    # Decimal should be tolerated (coerced), not crash.
    monkeypatch.setenv("VERIFIER_LATENCY_BUDGET_MS", "42.5")
    r = _post_guardrail("hi")
    assert r.status_code == 200
    assert "request_id" in r.json()


def test_latency_budget_env_negative_treated_as_unset(monkeypatch):
    monkeypatch.setenv("VERIFIER_LATENCY_BUDGET_MS", "-1")
    r = _post_guardrail("world")
    assert r.status_code == 200
    assert "request_id" in r.json()


def test_latency_budget_env_blank_treated_as_unset(monkeypatch):
    monkeypatch.setenv("VERIFIER_LATENCY_BUDGET_MS", "")
    r = _post_guardrail("ok")
    assert r.status_code == 200
    assert "request_id" in r.json()
