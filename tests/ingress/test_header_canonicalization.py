from __future__ import annotations

import pytest
from fastapi import Request
from starlette.testclient import TestClient

from app.main import create_app


@pytest.fixture()
def make_app():
    def _factory():
        app = create_app()

        @app.get("/canon-state")
        async def canon_state(request: Request):
            headers = dict(getattr(request.state, "headers_canon", {}))
            rid = getattr(request.state, "request_id", None)
            return {"headers": headers, "request_id": rid}

        return app

    return _factory


def test_canon_map_has_trimmed_values(make_app) -> None:
    with TestClient(make_app()) as client:
        response = client.get("/canon-state", headers={"X-REQUEST-id": "  abc-123  "})
        assert response.status_code == 200
        body = response.json()
        assert body["headers"]["X-Request-ID"] == "abc-123"
        assert body["request_id"] == "abc-123"
        health = client.get("/health", headers={"X-REQUEST-id": "  abc-123  "})
        assert health.status_code == 200
        assert health.headers["X-Request-ID"] == "  abc-123  "


def test_mixed_case_and_padding_for_tenant_bot(make_app) -> None:
    with TestClient(make_app()) as client:
        headers = {"x-guardrail-tenant": "  Team  One  ", "X-GUARDRAIL-bot": "  Chat  "}
        response = client.get("/canon-state", headers=headers)
        assert response.status_code == 200
        body = response.json()["headers"]
        assert body["X-Guardrail-Tenant"] == "Team One"
        assert body["X-Guardrail-Bot"] == "Chat"
        parity = client.get(
            "/health",
            headers={"X-Guardrail-Tenant": "Team One", "X-Guardrail-Bot": "Chat"},
        )
        assert parity.status_code == 200


def test_request_id_lowercase_header_roundtrips(make_app) -> None:
    with TestClient(make_app()) as client:
        response = client.get("/health", headers={"x-request-id": "rid-lower"})
        assert response.status_code == 200
        assert response.headers["X-Request-ID"] == "rid-lower"
