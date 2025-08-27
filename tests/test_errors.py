import importlib
import os

from fastapi import FastAPI
from fastapi.testclient import TestClient


def _build_app() -> FastAPI:
    os.environ["API_KEY"] = "unit-test-key"
    import app.config as cfg
    importlib.reload(cfg)
    import app.main as main
    importlib.reload(main)
    return main.build_app()


def _make_client(app: FastAPI) -> TestClient:
    return TestClient(app)


def test_404_has_code_and_request_id():
    app = _build_app()
    client = _make_client(app)
    r = client.get("/no-such-route")
    assert r.status_code == 404
    body = r.json()
    assert body.get("code") == "not_found"
    assert isinstance(body.get("request_id"), str)
    assert "X-Request-ID" in r.headers


def test_413_has_code_and_request_id():
    app = _build_app()
    client = _make_client(app)
    os.environ["MAX_PROMPT_CHARS"] = "8"
    r = client.post(
        "/guardrail",
        json={"prompt": "X" * 64},
        headers={"X-API-Key": "unit-test-key"},
    )
    assert r.status_code == 413
    body = r.json()
    assert body.get("code") == "payload_too_large"
    assert "request_id" in body


def test_429_has_retry_after_and_code():
    os.environ["RATE_LIMIT_ENABLED"] = "true"
    os.environ["RATE_LIMIT_PER_MINUTE"] = "2"
    os.environ["RATE_LIMIT_BURST"] = "2"

    app = _build_app()
    client = _make_client(app)
    h = {"X-API-Key": "unit-test-key"}

    assert client.post("/guardrail", json={"prompt": "1"}, headers=h).status_code == 200
    assert client.post("/guardrail", json={"prompt": "2"}, headers=h).status_code == 200
    r = client.post("/guardrail", json={"prompt": "3"}, headers=h)
    assert r.status_code == 429
    body = r.json()
    assert body.get("code") == "rate_limited"
    assert isinstance(body.get("retry_after"), int)
    assert "Retry-After" in r.headers
    assert "X-Request-ID" in r.headers


def test_500_has_internal_error_with_request_id():
    # Build app and add a route that raises at runtime
    app = _build_app()

    def boom():
        raise RuntimeError("boom")

    app.add_api_route("/boom", boom, methods=["GET"])

    client = _make_client(app)
    r = client.get("/boom")
    assert r.status_code == 500
    body = r.json()
    assert body.get("code") == "internal_error"
    assert "request_id" in body
    assert "X-Request-ID" in r.headers
