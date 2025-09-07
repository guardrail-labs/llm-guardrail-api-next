import importlib
import os
from contextlib import contextmanager

from fastapi import FastAPI
from fastapi.testclient import TestClient


@contextmanager
def temp_env(**kwargs):
    """Temporarily set env vars; restore original values on exit."""
    old = {k: os.environ.get(k) for k in kwargs}
    try:
        for k, v in kwargs.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = str(v)
        yield
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _build_app() -> FastAPI:
    # Always ensure API key is present
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
    # Limit only within this test
    with temp_env(MAX_PROMPT_CHARS="8"):
        app = _build_app()
        client = _make_client(app)
        r = client.post(
            "/guardrail/",
            json={"prompt": "X" * 64},
            headers={"X-API-Key": "unit-test-key"},
        )
        assert r.status_code == 413
        body = r.json()
        assert body.get("code") == "payload_too_large"
        assert "request_id" in body


def test_429_has_retry_after_and_code():
    # Enable rate limiting only for this test
    with temp_env(RATE_LIMIT_ENABLED="true", RATE_LIMIT_PER_MINUTE="2", RATE_LIMIT_BURST="2"):
        app = _build_app()
        client = _make_client(app)
        h = {"X-API-Key": "unit-test-key"}

        assert client.post("/guardrail/", json={"prompt": "1"}, headers=h).status_code == 200
        assert client.post("/guardrail/", json={"prompt": "2"}, headers=h).status_code == 200

        r = client.post("/guardrail/", json={"prompt": "3"}, headers=h)
        assert r.status_code == 429
        body = r.json()
        assert body.get("detail") == "rate limit exceeded"
        assert "Retry-After" in r.headers
        assert "X-Request-ID" in r.headers


def test_500_has_internal_error_with_request_id():
    # Do not modify env; just ensure 500 is returned as JSON.
    app = _build_app()

    def boom():
        raise RuntimeError("boom")

    app.add_api_route("/boom", boom, methods=["GET"])

    # Important: prevent TestClient from raising the server exception
    client = TestClient(app, raise_server_exceptions=False)
    r = client.get("/boom")
    assert r.status_code == 500
    body = r.json()
    assert body.get("code") == "internal_error"
    assert "request_id" in body
    assert "X-Request-ID" in r.headers
