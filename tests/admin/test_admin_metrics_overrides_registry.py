from fastapi.testclient import TestClient

from app.main import create_app


def test_overrides_endpoint_works_singleprocess(monkeypatch):
    monkeypatch.delenv("PROMETHEUS_MULTIPROC_DIR", raising=False)

    app = create_app()
    with TestClient(app) as client:
        response = client.get("/admin/api/metrics/mitigation-overrides")
        assert response.status_code == 200

        payload = response.json()
        assert set(payload["totals"].keys()) == {"block", "clarify", "redact"}
        assert isinstance(payload["since_ms"], int)
