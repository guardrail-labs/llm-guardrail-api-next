from fastapi.testclient import TestClient


def test_overrides_endpoint_shape(client: TestClient) -> None:
    response = client.get("/admin/api/metrics/mitigation-overrides")
    assert response.status_code == 200
    payload = response.json()
    assert "totals" in payload and "since_ms" in payload
    totals = payload["totals"]
    assert all(key in totals for key in ("block", "clarify", "redact"))
    assert isinstance(totals["block"], int)
    assert isinstance(payload["since_ms"], int)
