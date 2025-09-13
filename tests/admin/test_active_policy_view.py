from fastapi.testclient import TestClient

from app.main import create_app


def test_active_policy_view():
    client = TestClient(create_app())
    r = client.get("/admin/policies/active")
    assert r.status_code == 200
    j = r.json()
    assert "policy_version" in j
    assert "env_toggles" in j and isinstance(j["env_toggles"], dict)
    assert "decision_map" in j and isinstance(j["decision_map"], dict)
