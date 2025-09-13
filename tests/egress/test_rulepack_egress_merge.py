import pytest
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from app.main import app as main_app

router = APIRouter()


@router.get("/demo/rulepack-egress-json")
def demo():
    return JSONResponse({"msg": "contact me at a@gmail.com", "ssn": "111-22-3333"})


@pytest.fixture
def app():
    return main_app


@pytest.fixture
def client(app):
    return TestClient(app)


def test_egress_redacts_with_rulepacks(client, monkeypatch, app):
    monkeypatch.setenv("EGRESS_FILTER_ENABLED", "1")
    monkeypatch.setenv("RULEPACKS_ENFORCE", "1")
    monkeypatch.setenv("RULEPACKS_ACTIVE", "hipaa,gdpr")
    try:
        app.include_router(router)
    except Exception:
        pass
    r = client.get("/demo/rulepack-egress-json")
    assert r.status_code == 200
    j = r.json()
    assert j["msg"].endswith("[REDACTED-EMAIL]")
    assert j["ssn"] == "[REDACTED-SSN]"
