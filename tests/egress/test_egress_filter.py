from fastapi.responses import PlainTextResponse
from fastapi.testclient import TestClient

from app.main import app


@app.get("/egress-json")
def _egress_json():
    return {"email": "user@example.com"}


@app.get("/egress-text")
def _egress_text():
    return PlainTextResponse("contact: user@example.com")


client = TestClient(app)


def test_egress_redacts_email_json():
    r = client.get("/egress-json")
    assert r.status_code == 200
    assert r.json()["email"] == "[REDACTED-EMAIL]"


def test_egress_redacts_text_plain():
    r = client.get("/egress-text")
    assert r.status_code == 200
    assert "[REDACTED-EMAIL]" in r.text
