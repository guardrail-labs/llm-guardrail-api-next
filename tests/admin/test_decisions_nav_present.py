from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.routes import admin_decisions_api as dec


def test_nav_in_decisions_page(monkeypatch):
    app = FastAPI()
    app.include_router(dec.router)
    client = TestClient(app)
    response = client.get("/admin/decisions", headers={"accept": "text/html"})
    assert response.status_code == 200
    # nav links present
    assert "/admin" in response.text
    assert "/admin/policy/current" in response.text
