from fastapi import FastAPI
from fastapi.testclient import TestClient


def test_validate_includes_lints(monkeypatch):
    monkeypatch.setenv("ADMIN_API_KEY", "k")
    app = FastAPI()
    from app.routes.admin_policy_validate import router as r

    app.include_router(r)
    client = TestClient(app)
    body = {
        "csrf_token": "x",
        "policy": {
            "rules": {
                "redact": [
                    {"id": "dup", "pattern": "x"},
                    {"id": "dup", "pattern": "y"},
                ]
            }
        },
    }
    response = client.post(
        "/admin/api/policy/validate",
        headers={"X-Admin-Key": "k", "Cookie": "csrf=x", "X-CSRF-Token": "x"},
        json=body,
    )
    assert response.status_code in (200, 422)
    payload = response.json()
    assert "lints" in payload
    assert any(item.get("code") == "duplicate_id" for item in payload["lints"])
