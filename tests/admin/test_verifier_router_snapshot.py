from __future__ import annotations

from starlette.testclient import TestClient

from app.main import create_app
from app.services.verifier import _ROUTER  # singleton used by the route


def test_verifier_router_snapshot_endpoint_returns_snapshots() -> None:
    # Seed a snapshot
    _ROUTER.rank("t1", "b1", ["a", "b"])

    client = TestClient(create_app())

    r = client.get("/admin/api/verifier/router/snapshot")
    assert r.status_code == 200

    body = r.json()
    assert isinstance(body, list)
    # Entry resembles what router_snapshot test expects
    assert any(
        isinstance(entry, dict)
        and entry.get("tenant") == "t1"
        and entry.get("bot") == "b1"
        and isinstance(entry.get("order"), list)
        and isinstance(entry.get("last_ranked_at"), float)
        for entry in body
    )
