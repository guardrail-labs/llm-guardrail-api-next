from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import create_app
from app.services.mitigation_prefs import _STORE


def _client() -> TestClient:
    app = create_app()
    return TestClient(app)


def setup_function() -> None:
    _STORE.clear()


def test_get_default_mode_returns_default() -> None:
    client = _client()
    resp = client.get(
        "/admin/api/mitigation/modes",
        params={"tenant": "t1", "bot": "b1"},
    )
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["mode"] in {"block", "clarify", "redact"}
    assert payload["source"] in {"default", "explicit"}


def test_put_sets_explicit_and_roundtrips() -> None:
    client = _client()
    resp = client.put(
        "/admin/api/mitigation/modes",
        json={"tenant": "t1", "bot": "b1", "mode": "block"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["mode"] == "block"
    assert body["source"] == "explicit"


def test_put_rejects_invalid_mode() -> None:
    client = _client()
    resp = client.put(
        "/admin/api/mitigation/modes",
        json={"tenant": "t1", "bot": "b1", "mode": "nope"},
    )
    assert resp.status_code == 400
