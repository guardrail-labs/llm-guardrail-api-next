import re

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from fastapi.testclient import TestClient
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from app.middleware.egress_redact import EgressRedactMiddleware
from app.services import policy_redact as pr
from app.services.policy_redact import RedactRule


def _make_app(
    text_payload: str = "token sk_test_ABCDEF123456 is here",
    json_payload=None,
) -> FastAPI:
    app = FastAPI()
    app.add_middleware(EgressRedactMiddleware)

    @app.get("/text")
    def text():  # pragma: no cover - simple route
        return PlainTextResponse(text_payload)

    @app.get("/json")
    def js():  # pragma: no cover - simple route
        return json_payload or {"note": text_payload}

    @app.get("/metrics")
    def metrics():
        data = generate_latest()
        return PlainTextResponse(data.decode("utf-8"), media_type=CONTENT_TYPE_LATEST)

    return app


def test_redacts_text_and_counts(monkeypatch):
    monkeypatch.setenv("EGRESS_REDACT_ENABLED", "true")
    rules = [
        RedactRule(
            "secret-key",
            r"(sk_test|sk_live)_[A-Za-z0-9]{10,}",
            "[REDACTED:KEY]",
            0,
        ),
        RedactRule(
            "email",
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
            "[REDACTED:EMAIL]",
            re.IGNORECASE,
        ),
    ]
    monkeypatch.setattr(pr, "get_redact_rules", lambda: rules)

    app = _make_app()
    client = TestClient(app)

    r = client.get("/text")
    assert r.status_code == 200
    assert "[REDACTED:KEY]" in r.text
    assert "sk_test_" not in r.text

    m = client.get("/metrics")
    assert m.status_code == 200
    text = m.text
    assert "guardrail_egress_redactions_total" in text
    assert 'rule_id="secret-key"' in text


def test_json_redaction(monkeypatch):
    monkeypatch.setenv("EGRESS_REDACT_ENABLED", "true")
    monkeypatch.setattr(
        pr,
        "get_redact_rules",
        lambda: [RedactRule("secret-key", r"sk_test_[A-Za-z0-9]{10,}", "[X]")],
    )
    payload = {
        "a": "keep",
        "b": "sk_test_ZZZZZZZZZZZZZ",
        "c": ["x", "sk_test_YYYYYYYYYYYY"],
    }
    app = _make_app(text_payload="", json_payload=payload)
    client = TestClient(app)

    r = client.get("/json")
    assert r.status_code == 200
    data = r.json()
    assert data["b"] == "[X]"
    assert data["c"][1] == "[X]"


def test_toggle_respected(monkeypatch):
    monkeypatch.delenv("EGRESS_REDACT_ENABLED", raising=False)
    monkeypatch.setattr(pr, "get_redact_rules", lambda: [RedactRule("r", r"secret", "[X]")])

    app = _make_app(text_payload="secret value")
    client = TestClient(app)
    r = client.get("/text")
    assert r.text == "secret value"
