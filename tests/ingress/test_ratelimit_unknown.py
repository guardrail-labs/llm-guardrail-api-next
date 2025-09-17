from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.middleware.rate_limit import RateLimitMiddleware


def _make_app():
    app = FastAPI()
    app.add_middleware(RateLimitMiddleware)

    @app.get("/echo")
    def echo():
        return {"ok": True}

    return app


def test_unknown_bypasses_by_default(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("RATE_LIMIT_RPS", "1")
    monkeypatch.setenv("RATE_LIMIT_BURST", "1")
    monkeypatch.delenv("RATE_LIMIT_ENFORCE_UNKNOWN", raising=False)

    app = _make_app()
    client = TestClient(app)

    response_1 = client.get("/echo")
    response_2 = client.get("/echo")

    assert response_1.status_code == 200
    assert response_2.status_code == 200


def test_unknown_enforced_when_flag_true(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("RATE_LIMIT_RPS", "1")
    monkeypatch.setenv("RATE_LIMIT_BURST", "1")
    monkeypatch.setenv("RATE_LIMIT_ENFORCE_UNKNOWN", "true")

    app = _make_app()
    client = TestClient(app)

    response_1 = client.get("/echo")
    response_2 = client.get("/echo")

    assert response_1.status_code == 200
    assert response_2.status_code == 429
    assert "Retry-After" in response_2.headers


def test_known_identities_still_limited(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("RATE_LIMIT_RPS", "1")
    monkeypatch.setenv("RATE_LIMIT_BURST", "1")

    app = _make_app()
    client = TestClient(app)
    headers = {"X-Guardrail-Tenant": "acme", "X-Guardrail-Bot": "ui"}

    response_1 = client.get("/echo", headers=headers)
    response_2 = client.get("/echo", headers=headers)

    assert response_1.status_code == 200
    assert response_2.status_code == 429


def test_skip_metric_emitted_on_bypass(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.delenv("RATE_LIMIT_ENFORCE_UNKNOWN", raising=False)

    app = _make_app()
    client = TestClient(app)

    client.get("/echo")

    metrics_response = client.get("/metrics")
    if metrics_response.status_code == 200:
        assert "guardrail_rate_limit_skipped_total" in metrics_response.text
        assert '{reason="unknown_identity"}' in metrics_response.text
