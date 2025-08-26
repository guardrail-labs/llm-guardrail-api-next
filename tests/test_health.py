from fastapi.testclient import TestClient
from app.main import build_app

client = TestClient(build_app())

def test_healthz():
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json().get("status") == "ok"
