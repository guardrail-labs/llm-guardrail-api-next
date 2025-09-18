from __future__ import annotations

import importlib
import pathlib

import pytest
import yaml
from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from fastapi.testclient import TestClient


def _merged_secrets_policy() -> dict[str, dict[str, list[dict[str, str]]]]:
    pack = yaml.safe_load(pathlib.Path("policy/packs/secrets_redact.yaml").read_text()) or {}
    rules = (pack.get("rules") or {}).get("redact") or []
    return {"rules": {"redact": rules}}


def _app(monkeypatch: pytest.MonkeyPatch) -> FastAPI:
    app = FastAPI()

    from app.middleware.egress_redact import EgressRedactMiddleware

    app.add_middleware(EgressRedactMiddleware)

    monkeypatch.setenv("EGRESS_REDACT_ENABLED", "1")

    policy_module = importlib.import_module("app.services.policy")
    monkeypatch.setattr(policy_module, "get", lambda: _merged_secrets_policy(), raising=False)
    monkeypatch.setattr(policy_module, "get_active_policy", lambda: _merged_secrets_policy())
    monkeypatch.setattr(policy_module, "current_rules_version", lambda: "test-secrets")

    @app.get("/echo")
    def echo() -> PlainTextResponse:
        body = (
            "ghp_1234567890abcdef1234567890ABCDEFabcd "
            "xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx "
            "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX "
            "sk_test_1234567890abcdefghijklmnOPQR "
            "AC0123456789abcdef0123456789ABCDEF "
        )
        return PlainTextResponse(body, media_type="text/plain; charset=utf-8")

    return app


def test_e2e_secret_redaction_occurs(monkeypatch: pytest.MonkeyPatch) -> None:
    app = _app(monkeypatch)
    client = TestClient(app)
    response = client.get("/echo")
    assert response.status_code == 200
    text = response.text
    assert "ghp_1234567890abcdef1234567890ABCDEFabcd" not in text
    assert "xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx" not in text
    assert "hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX" not in text
    assert "sk_test_1234567890abcdefghijklmnOPQR" not in text
    assert "AC0123456789abcdef0123456789ABCDEF" not in text
