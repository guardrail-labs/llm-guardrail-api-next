import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


@pytest.mark.parametrize("force", ["1"])
def test_batch_evaluate_awaits_verifier(force: str) -> None:
    payload = {"items": [{"text": "test", "request_id": "r1"}]}
    r = client.post(
        "/guardrail/batch_evaluate",
        json=payload,
        headers={"X-Force-Unclear": force},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["count"] == 1
    assert "items" in body

