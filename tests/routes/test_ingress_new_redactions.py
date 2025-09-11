from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_ingress_redacts_slack_and_ssn_allows() -> None:
    text = "xoxb-1234567890-ABCDEFGH and 123-45-6789"
    r = client.post("/guardrail/evaluate", json={"text": text})
    j = r.json()
    assert r.status_code == 200
    assert j["action"] == "allow"
    assert "[REDACTED:SLACK_TOKEN]" in j["transformed_text"]
    assert "[REDACTED:SSN]" in j["transformed_text"]
    assert j["redactions"] >= 2
