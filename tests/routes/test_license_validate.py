from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import create_app


def test_license_validate_endpoint_exists() -> None:
    app = create_app()
    client = TestClient(app)

    response = client.get("/license/validate")
    assert response.status_code == 200

    body = response.json()
    assert "status" in body
    assert isinstance(body["status"], str)
