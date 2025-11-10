from typing import Dict

import pytest
from fastapi.testclient import TestClient

from app import config as app_config
from app.main import create_app
from app.security import service_tokens
from app.services import config as services_config
from app.services import decisions_store


def _auth(token: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def scope_metrics_client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("SCOPE_AUTOCONSTRAIN_ENABLED", "true")
    monkeypatch.setattr(services_config, "SCOPE_AUTOCONSTRAIN_ENABLED", True, raising=False)

    secret = "scope-metrics-secret"
    monkeypatch.setenv("SERVICE_TOKEN_SECRET", secret)
    monkeypatch.setattr(app_config, "SERVICE_TOKEN_SECRET", secret, raising=False)
    service_tokens.reset_memory_store()

    monkeypatch.setattr(
        decisions_store,
        "list_with_cursor",
        lambda **_: ([], None, None),
        raising=False,
    )
    monkeypatch.setattr(
        "app.routes.admin_decisions_api.list_with_cursor",
        lambda **_: ([], None, None),
        raising=False,
    )

    app = create_app()
    return TestClient(app)


def test_scope_autoconstraint_metric_records_multi(scope_metrics_client: TestClient) -> None:
    token_payload = service_tokens.mint(
        role="admin",
        tenants=["acme", "beta"],
        bots=["assistant", "reviewer"],
    )
    token = str(token_payload["token"])

    response = scope_metrics_client.get(
        "/admin/api/decisions",
        headers=_auth(token),
    )
    assert response.status_code == 200

    metrics_response = scope_metrics_client.get("/metrics")
    assert metrics_response.status_code == 200

    body = metrics_response.text
    matching_lines = [
        line
        for line in body.splitlines()
        if line.startswith("guardrail_scope_autoconstraint_total")
        and 'endpoint="decisions_list"' in line
        and 'mode="on"' in line
        and 'result="constrained"' in line
        and 'multi="true"' in line
    ]
    assert matching_lines
