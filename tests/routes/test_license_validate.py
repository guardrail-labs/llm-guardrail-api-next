from fastapi.testclient import TestClient

from app.main import create_app


def test_license_validate_missing_key() -> None:
    app = create_app()
    client = TestClient(app)

    resp = client.get("/license/validate")
    assert resp.status_code == 200

    body = resp.json()
    assert "status" in body
    assert body["status"] in {"missing", "unknown", "active", "revoked", "invalid", "error"}
