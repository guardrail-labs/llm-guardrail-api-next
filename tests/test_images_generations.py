from typing import Any, Dict, List

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.routes import openai_compat as compat
from app.routes.openai_compat import azure_router, router as oai_router


@pytest.fixture
def client() -> TestClient:
    """
    Minimal FastAPI app exposing the OpenAI/Azure-compatible routes.
    Keeps the scope local to this test module, avoiding repo-wide fixture deps.
    """
    app = FastAPI()
    app.include_router(oai_router)
    app.include_router(azure_router)
    return TestClient(app)


def test_images_generations_allow(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    # allow everything deterministically
    monkeypatch.setattr(
        compat,
        "sanitize_text",
        lambda text, debug=False: (text, [], 0, {}),
    )

    def _allow(_text: str) -> Dict[str, Any]:
        return {"action": "allow", "rule_hits": [], "decisions": []}

    monkeypatch.setattr(compat, "evaluate_prompt", _allow)

    import app.telemetry.metrics as metrics

    before = metrics.get_decisions_family_total("allow")
    resp = client.post(
        "/v1/images/generations",
        json={"prompt": "a cat on a mat", "n": 2},
    )
    assert resp.status_code == 200
    body: Dict[str, Any] = resp.json()
    data: List[Dict[str, str]] = body["data"]
    assert len(data) == 2
    assert all("b64_json" in d and d["b64_json"] for d in data)

    # guard headers present
    assert resp.headers["X-Guardrail-Policy-Version"]
    assert resp.headers["X-Guardrail-Ingress-Action"] == "allow"
    assert resp.headers["X-Guardrail-Egress-Action"] == "allow"

    after = metrics.get_decisions_family_total("allow")
    assert after >= before + 1


def test_images_generations_deny(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    # deny path deterministically
    monkeypatch.setattr(
        compat,
        "sanitize_text",
        lambda text, debug=False: (text, [], 0, {}),
    )

    def _deny(_text: str) -> Dict[str, Any]:
        return {"action": "deny", "rule_hits": [], "decisions": []}

    monkeypatch.setattr(compat, "evaluate_prompt", _deny)

    resp = client.post(
        "/v1/images/generations",
        json={"prompt": "bad stuff", "n": 1},
    )
    assert resp.status_code == 400

    # headers from HTTPException should be present
    assert resp.headers["X-Guardrail-Policy-Version"]
    assert resp.headers["X-Guardrail-Ingress-Action"] == "deny"
    assert resp.headers["X-Guardrail-Egress-Action"] == "skipped"
