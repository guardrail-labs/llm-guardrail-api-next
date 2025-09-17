import importlib
import os
import re

from fastapi.testclient import TestClient

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)


def _make_client():
    os.environ["API_KEY"] = "unit-test-key"
    os.environ["SEC_HEADERS_ENABLED"] = "1"

    import app.config as cfg

    importlib.reload(cfg)
    import app.main as main

    importlib.reload(main)

    return TestClient(main.build_app())


def test_request_id_generated_and_echoed():
    client = _make_client()
    r = client.post("/guardrail/", json={"prompt": "hello"}, headers={"X-API-Key": "unit-test-key"})
    assert r.status_code == 200

    rid = r.headers.get("X-Request-ID")
    assert rid and _UUID_RE.match(rid), "response must include a valid X-Request-ID"
    assert isinstance(r.json().get("request_id"), str)


def test_request_id_passthrough_from_client():
    client = _make_client()
    custom = "123e4567-e89b-12d3-a456-426614174000"
    r = client.post(
        "/guardrail/",
        json={"prompt": "echo"},
        headers={"X-API-Key": "unit-test-key", "X-Request-ID": custom},
    )
    assert r.status_code == 200
    assert r.headers.get("X-Request-ID") == custom


def test_security_headers_present_on_health():
    client = _make_client()
    r = client.get("/health")
    assert r.status_code == 200
    h = r.headers
    assert h.get("X-Content-Type-Options") == "nosniff"
    assert h.get("X-Frame-Options") == "DENY"
    assert h.get("Referrer-Policy") == "no-referrer"


def test_retry_after_and_request_id_on_429(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("RATE_LIMIT_PER_MINUTE", "2")
    monkeypatch.setenv("RATE_LIMIT_BURST", "2")
    monkeypatch.setenv("RATE_LIMIT_ENFORCE_UNKNOWN", "true")

    client = _make_client()
    headers = {"X-API-Key": "unit-test-key"}

    assert client.post("/guardrail/", json={"prompt": "1"}, headers=headers).status_code == 200
    assert client.post("/guardrail/", json={"prompt": "2"}, headers=headers).status_code == 200
    r = client.post("/guardrail/", json={"prompt": "3"}, headers=headers)
    assert r.status_code == 429
    assert r.headers.get("Retry-After") is not None
    assert r.headers.get("X-Request-ID") is not None
    assert "rate limit exceeded" in r.json().get("detail", "").lower()
