from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_egress_redacts_github_pat_allows() -> None:
    body = {"text": "token ghp_abcdefghijklmnopqrstuvwxyz1234567890 next"}
    r = client.post("/guardrail/egress_evaluate", json=body)
    j = r.json()
    assert r.status_code == 200
    assert j["action"] == "allow"
    assert "[REDACTED:GITHUB_PAT]" in j["transformed_text"]


def test_egress_denies_private_key_envelope() -> None:
    body = {"text": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"}
    r = client.post("/guardrail/egress_evaluate", json=body)
    j = r.json()
    assert r.status_code == 200
    assert j["action"] == "deny"


def test_egress_redacts_jwt() -> None:
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
        "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
    )
    r = client.post("/guardrail/egress_evaluate", json={"text": f"token {jwt}"})
    j = r.json()
    assert r.status_code == 200
    assert j["action"] == "allow"
    assert "[REDACTED:JWT]" in j["transformed_text"]
