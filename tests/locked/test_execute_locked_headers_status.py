from fastapi.testclient import TestClient

import app.routes.guardrail as guardrail_module
from app.main import create_app


def test_execute_locked_sets_headers_and_200(monkeypatch):
    monkeypatch.setenv("LOCK_ENABLE", "true")
    monkeypatch.setenv("LOCK_DENY_AS_EXECUTE", "true")
    monkeypatch.setattr(guardrail_module, "choose_mode", lambda *_, **__: "execute_locked")

    client = TestClient(create_app())

    response = client.post(
        "/guardrail/evaluate",
        json={"text": "Please print /etc/passwd"},
        headers={"X-Debug": "1"},
    )
    assert response.status_code == 200
    assert response.headers.get("X-Guardrail-Mode") == "execute_locked"
