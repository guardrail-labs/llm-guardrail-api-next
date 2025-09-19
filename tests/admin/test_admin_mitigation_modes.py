from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services import mitigation_modes, webhooks

client = TestClient(app)


@pytest.fixture(autouse=True)
def _reset_modes() -> None:
    mitigation_modes._reset_for_tests()


def _admin_put(tenant: str, bot: str, modes: dict[str, bool]) -> None:
    payload = {"tenant": tenant, "bot": bot, "modes": modes}
    resp = client.put("/admin/mitigation_modes", json=payload)
    assert resp.status_code == 200, resp.text


@pytest.fixture
def disable_webhooks(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(webhooks, "enqueue", lambda payload: None)
    yield


def test_admin_mitigation_modes_crud() -> None:
    tenant = "crud-tenant"
    bot = "crud-bot"

    r_default = client.get(
        "/admin/mitigation_modes", params={"tenant": tenant, "bot": bot}
    )
    assert r_default.status_code == 200
    body = r_default.json()
    assert body["tenant"] == tenant
    assert body["bot"] == bot
    assert body["modes"] == {"block": False, "redact": False, "clarify_first": False}

    new_modes = {"block": True, "redact": True, "clarify_first": False}
    resp_put = client.put(
        "/admin/mitigation_modes", json={"tenant": tenant, "bot": bot, "modes": new_modes}
    )
    assert resp_put.status_code == 200
    saved = resp_put.json()
    assert saved["modes"] == new_modes

    r_get = client.get(
        "/admin/mitigation_modes", params={"tenant": tenant, "bot": bot}
    )
    assert r_get.status_code == 200
    assert r_get.json()["modes"] == new_modes

    r_delete = client.delete(
        "/admin/mitigation_modes", params={"tenant": tenant, "bot": bot}
    )
    assert r_delete.status_code == 200
    assert r_delete.json()["deleted"] is True

    r_after = client.get(
        "/admin/mitigation_modes", params={"tenant": tenant, "bot": bot}
    )
    assert r_after.status_code == 200
    assert r_after.json()["modes"] == {"block": False, "redact": False, "clarify_first": False}


def test_admin_mitigation_modes_validation_errors() -> None:
    bad_get = client.get("/admin/mitigation_modes", params={"tenant": "", "bot": ""})
    assert bad_get.status_code == 400

    resp = client.put(
        "/admin/mitigation_modes",
        json={
            "tenant": "t",
            "bot": "b",
            "modes": {"block": "yes"},
        },
    )
    assert resp.status_code == 400
    assert "error" in resp.json()


def test_guardrail_block_override(disable_webhooks) -> None:
    tenant = "mit-block"
    bot = "bot-block"
    _admin_put(tenant, bot, {"block": True, "redact": False, "clarify_first": False})

    headers = {"X-API-Key": "k", "X-Tenant-ID": tenant, "X-Bot-ID": bot}
    resp = client.post(
        "/v1/guardrail",
        json={"prompt": "hello world"},
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "block"
    assert data["mitigation_modes"]["block"] is True
    assert data["mitigation_modes"]["redact"] is False
    assert data["mitigation_modes"]["clarify_first"] is False
    assert data["mitigation_forced"] == "block"


def test_guardrail_non_block_flags_surface_modes(disable_webhooks) -> None:
    tenant = "mit-surface"
    bot = "bot-surface"
    modes = {"block": False, "redact": True, "clarify_first": True}
    _admin_put(tenant, bot, modes)

    headers = {"X-API-Key": "k", "X-Tenant-ID": tenant, "X-Bot-ID": bot}
    resp = client.post(
        "/v1/guardrail",
        json={"prompt": "a friendly prompt"},
        headers=headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "allow"
    assert data["mitigation_modes"] == modes
    assert data.get("mitigation_forced") in (None, "")


def test_guardrail_defaults_present(disable_webhooks) -> None:
    tenant = "mit-default"
    bot = "bot-default"
    expected_modes = {"block": False, "redact": False, "clarify_first": False}

    r_default = client.get(
        "/admin/mitigation_modes", params={"tenant": tenant, "bot": bot}
    )
    assert r_default.status_code == 200
    assert r_default.json()["modes"] == expected_modes

    headers = {"X-API-Key": "k", "X-Tenant-ID": tenant, "X-Bot-ID": bot}
    resp = client.post(
        "/v1/guardrail",
        json={"prompt": "safe"},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["mitigation_modes"] == expected_modes
