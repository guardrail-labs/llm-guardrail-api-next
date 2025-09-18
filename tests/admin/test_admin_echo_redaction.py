import importlib

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture()
def admin_echo_app(monkeypatch: pytest.MonkeyPatch) -> FastAPI:
    monkeypatch.setenv("ADMIN_API_KEY", "k")
    monkeypatch.setenv("EGRESS_REDACT_ENABLED", "true")
    monkeypatch.setenv("ADMIN_RBAC_ENABLED", "true")

    policy_redact = importlib.import_module("app.services.policy_redact")
    egress_redact_text = importlib.import_module("app.services.egress.redact_text")

    monkeypatch.setattr(
        policy_redact,
        "get_redact_rules",
        lambda: [policy_redact.RedactRule("email", r"\b\S+@\S+\b")],
    )
    assert policy_redact.get_redact_rules()

    redacted, _ = egress_redact_text.redact_text("x@y.com")
    assert "x@y.com" not in redacted

    app = FastAPI()
    from app.routes.admin_echo import router as admin_echo_router

    app.include_router(admin_echo_router)

    from app.middleware.egress_redact import EgressRedactMiddleware

    app.add_middleware(EgressRedactMiddleware)
    return app


def test_admin_echo_requires_key_and_redacts(admin_echo_app: FastAPI) -> None:
    client = TestClient(admin_echo_app)

    response = client.get("/admin/echo", params={"text": "x@y.com"})
    assert response.status_code == 403

    authorized = client.get(
        "/admin/echo",
        params={"text": "x@y.com"},
        headers={"X-Admin-Key": "k"},
    )
    assert authorized.status_code == 200
    assert "x@y.com" not in authorized.text
