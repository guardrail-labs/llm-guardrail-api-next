import pytest
from starlette.testclient import TestClient

import app.routes.guardrail as guardrail_mod
from app.main import create_app


@pytest.fixture(autouse=True)
def _force_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("API_KEY", "unit-test-key")


def _auth_headers(extra: dict[str, str] | None = None) -> dict[str, str]:
    headers = {"X-API-Key": "unit-test-key"}
    if extra:
        headers.update(extra)
    return headers


def test_replay_includes_security_headers(client) -> None:
    payload = {"prompt": "check headers"}
    headers = _auth_headers({"X-Idempotency-Key": "security-hdr"})

    first = client.post("/v1/guardrail", json=payload, headers=headers)
    assert first.status_code == 200
    assert first.headers.get("X-Content-Type-Options") == "nosniff"
    assert first.headers.get("Idempotency-Replayed") == "false"
    assert first.headers.get("Idempotency-Replay-Count") is None

    second = client.post("/v1/guardrail", json=payload, headers=headers)
    assert second.status_code == first.status_code
    assert second.headers.get("Idempotency-Replayed") == "true"
    assert second.headers.get("X-Content-Type-Options") == "nosniff"
    assert second.headers.get("Idempotency-Replay-Count") == "1"


def test_replay_includes_cors_headers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CORS_ENABLED", "1")
    monkeypatch.setenv("CORS_ALLOW_ORIGINS", "https://example.com")

    app = create_app()
    origin = "https://example.com"
    headers = _auth_headers({"X-Idempotency-Key": "cors-hdr"})
    headers["Origin"] = origin

    with TestClient(app) as local_client:
        first = local_client.post("/v1/guardrail", json={"prompt": "cors"}, headers=headers)
        assert first.status_code == 200
        assert first.headers.get("Access-Control-Allow-Origin") == origin
        assert first.headers.get("Idempotency-Replay-Count") is None

        second = local_client.post("/v1/guardrail", json={"prompt": "cors"}, headers=headers)
        assert second.status_code == first.status_code
        assert second.headers.get("Idempotency-Replayed") == "true"
        assert second.headers.get("Access-Control-Allow-Origin") == origin
        assert second.headers.get("Idempotency-Replay-Count") == "1"


def test_replay_preserves_custom_headers(client, monkeypatch: pytest.MonkeyPatch) -> None:
    original_allow = guardrail_mod._respond_legacy_allow

    def _patched(prompt, request_id, rule_hits, policy_version, redactions):
        resp = original_allow(prompt, request_id, rule_hits, policy_version, redactions)
        resp.headers["X-Custom-Test"] = "1"
        return resp

    monkeypatch.setattr(guardrail_mod, "_respond_legacy_allow", _patched)

    payload = {"prompt": "custom header"}
    headers = _auth_headers({"X-Idempotency-Key": "custom-hdr"})

    first = client.post("/v1/guardrail", json=payload, headers=headers)
    assert first.status_code == 200
    assert first.headers.get("X-Custom-Test") == "1"
    assert first.headers.get("Idempotency-Replay-Count") is None

    second = client.post("/v1/guardrail", json=payload, headers=headers)
    assert second.status_code == first.status_code
    assert second.headers.get("Idempotency-Replayed") == "true"
    assert second.headers.get("X-Custom-Test") == "1"
    assert second.headers.get("Idempotency-Replay-Count") == "1"
