import io
from typing import Any, Dict, List

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.routes import openai_compat as compat
from app.routes.openai_compat import azure_router
from app.routes.openai_compat import router as oai_router


@pytest.fixture
def client() -> TestClient:
    app = FastAPI()
    app.include_router(oai_router)
    app.include_router(azure_router)
    return TestClient(app)


def test_images_edits_allow(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        compat,
        "sanitize_text",
        lambda text, debug=False: (text, [], 0, {}),
    )

    def _allow(_text: str) -> Dict[str, Any]:
        return {"action": "allow", "rule_hits": [], "decisions": []}

    monkeypatch.setattr(compat, "evaluate_prompt", _allow)

    fake_png = io.BytesIO(b"\x89PNG\r\n\x1a\n")
    files = {"image": ("in.png", fake_png, "image/png")}
    data = {"prompt": "edit this", "n": "2"}
    resp = client.post("/v1/images/edits", files=files, data=data)
    assert resp.status_code == 200
    body: Dict[str, Any] = resp.json()
    data_out: List[Dict[str, str]] = body["data"]
    assert len(data_out) == 2
    assert all("b64_json" in d and d["b64_json"] for d in data_out)
    assert resp.headers["X-Guardrail-Policy-Version"]
    assert resp.headers["X-Guardrail-Ingress-Action"] == "allow"
    assert resp.headers["X-Guardrail-Egress-Action"] == "allow"


def test_images_edits_deny(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        compat,
        "sanitize_text",
        lambda text, debug=False: (text, [], 0, {}),
    )

    def _deny(_text: str) -> Dict[str, Any]:
        return {"action": "deny", "rule_hits": [], "decisions": []}

    monkeypatch.setattr(compat, "evaluate_prompt", _deny)

    fake_png = io.BytesIO(b"\x89PNG\r\n\x1a\n")
    files = {"image": ("in.png", fake_png, "image/png")}
    data = {"prompt": "unsafe", "n": "1"}
    resp = client.post("/v1/images/edits", files=files, data=data)
    assert resp.status_code == 400
    assert resp.headers["X-Guardrail-Policy-Version"]
    assert resp.headers["X-Guardrail-Ingress-Action"] == "deny"
    assert resp.headers["X-Guardrail-Egress-Action"] == "skipped"
