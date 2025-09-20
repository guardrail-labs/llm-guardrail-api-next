from __future__ import annotations

from fastapi.testclient import TestClient


def test_overrides_endpoint_shape(client: TestClient) -> None:
    response = client.get("/admin/api/metrics/mitigation-overrides")
    assert response.status_code == 200
    payload = response.json()
    assert "totals" in payload
    assert "since_ms" in payload
    totals = payload["totals"]
    for key in ("block", "clarify", "redact"):
        assert key in totals
        assert isinstance(totals[key], int)
    assert isinstance(payload["since_ms"], int)
