from fastapi.testclient import TestClient
from app.main import build_app

client = TestClient(build_app())

def test_guardrail_allows_by_default():
    payload = {"prompt": "Hello, world!"}
    r = client.post("/guardrail", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert body["decision"] == "allow"
    assert isinstance(body["request_id"], str)
    assert "policy_version" in body
