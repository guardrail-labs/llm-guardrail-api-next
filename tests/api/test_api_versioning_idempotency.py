from __future__ import annotations

from typing import Dict

import pytest
from starlette.testclient import TestClient

import app.routes.guardrail as guardrail_mod


@pytest.fixture(autouse=True)
def _force_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("API_KEY", "unit-test-key")


def _auth_headers(extra: Dict[str, str] | None = None) -> Dict[str, str]:
    base = {"X-API-Key": "unit-test-key"}
    if extra:
        base.update(extra)
    return base


def test_v1_guardrail_matches_legacy(client) -> None:
    payload = {"prompt": "Hello from v1", "request_id": "parity"}

    legacy = client.post("/guardrail", json=payload, headers=_auth_headers())
    assert legacy.status_code == 200
    assert legacy.headers.get("Deprecation") == "true"

    v1 = client.post("/v1/guardrail", json=payload, headers=_auth_headers())
    assert v1.status_code == 200
    assert v1.headers.get("Deprecation") is None
    assert v1.json() == legacy.json()


def test_idempotent_replay_same_body(client) -> None:
    payload = {"prompt": "Replay me"}
    headers = _auth_headers({"X-Idempotency-Key": "abc123"})

    first = client.post("/v1/guardrail", json=payload, headers=headers)
    assert first.status_code == 200
    assert first.headers.get("Idempotency-Replayed") == "false"
    assert first.headers.get("Idempotency-Replay-Count") is None

    second = client.post("/v1/guardrail", json=payload, headers=headers)
    assert second.status_code == first.status_code
    assert second.headers.get("Idempotency-Replayed") == "true"
    assert second.headers.get("Idempotency-Replay-Count") == "1"
    assert second.json() == first.json()


def test_idempotent_same_key_different_body(client) -> None:
    headers = _auth_headers({"X-Idempotency-Key": "body-swap"})
    first = client.post(
        "/v1/guardrail",
        json={"prompt": "one", "request_id": "first"},
        headers=headers,
    )
    assert first.status_code == 200

    second = client.post(
        "/v1/guardrail",
        json={"prompt": "two", "request_id": "second"},
        headers=headers,
    )
    assert second.status_code == 200
    assert second.headers.get("Idempotency-Replayed") != "true"
    assert second.json().get("request_id") == "second"


def test_idempotency_skips_5xx(app, monkeypatch: pytest.MonkeyPatch) -> None:
    call_count = {"value": 0}

    def flaky_version() -> str:
        call_count["value"] += 1
        if call_count["value"] == 1:
            raise RuntimeError("boom")
        return "ok"

    monkeypatch.setattr(guardrail_mod, "current_rules_version", flaky_version)

    headers = _auth_headers({"X-Idempotency-Key": "retryable"})
    with TestClient(app, raise_server_exceptions=False) as local_client:
        failing = local_client.post("/v1/guardrail", json={"prompt": "broken"}, headers=headers)
        assert failing.status_code == 500
        assert failing.headers.get("Idempotency-Replayed") is None

        recovered = local_client.post(
            "/v1/guardrail", json={"prompt": "broken"}, headers=headers
        )
        assert recovered.status_code == 200
        assert recovered.headers.get("Idempotency-Replayed") != "true"
    assert call_count["value"] >= 2


def test_rejects_long_idempotency_key(client) -> None:
    headers = _auth_headers({"X-Idempotency-Key": "x" * 201})
    r = client.post("/v1/guardrail", json={"prompt": "hi"}, headers=headers)
    assert r.status_code == 400
    body = r.json()
    assert body.get("code") == "bad_request"
    assert body.get("detail") == "invalid idempotency key"


def test_batch_idempotency_replay(client) -> None:
    payload = {"items": [{"text": "one"}, {"text": "two"}]}
    headers = _auth_headers({"X-Idempotency-Key": "batch-key"})

    first = client.post("/v1/batch/batch_evaluate", json=payload, headers=headers)
    assert first.status_code == 200
    assert first.headers.get("Idempotency-Replayed") == "false"
    assert first.headers.get("Idempotency-Replay-Count") is None

    second = client.post("/v1/batch/batch_evaluate", json=payload, headers=headers)
    assert second.status_code == 200
    assert second.headers.get("Idempotency-Replayed") == "true"
    assert second.headers.get("Idempotency-Replay-Count") == "1"
    assert second.json() == first.json()
