from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import create_app


def test_admin_egress_incidents_returns_recent():
    c = TestClient(create_app())

    c.post(
        "/guardrail/sanitize",
        json={"text": "pw: password=abc123", "tenant": "acme", "bot": "b1"},
    )
    c.post(
        "/guardrail/sanitize",
        json={"text": "email me at a@b.co", "tenant": "acme", "bot": "b1"},
    )

    r = c.get("/admin/api/egress/incidents?tenant=acme&bot=b1&limit=2")
    assert r.status_code == 200
    items = r.json()["items"]
    assert len(items) >= 2
    assert items[0]["tenant"] == "acme"
    assert items[0]["bot"] == "b1"
    assert items[0]["redactions"] >= 1
    assert isinstance(items[0]["reasons"], list)
