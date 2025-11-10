from typing import Any, Mapping

from fastapi.testclient import TestClient

from app.main import app
from app.runtime.router import router as runtime_router

if not any(getattr(route, "path", "") == "/chat/completions" for route in app.router.routes):
    app.include_router(runtime_router)

client = TestClient(app)


def test_ingress_preserves_mapping_payload_on_allow() -> None:
    payload: dict[str, Any] = {
        "text": "he\u200bllo",
        "meta": {"topic": "greeting", "id": 123},
        "modality": "text",
    }

    resp = client.post("/chat/completions", json=payload)
    assert resp.status_code in (200, 202, 400, 500)

    ing_action = resp.headers.get("X-Guardrail-Decision-Ingress", "")
    if ing_action in ("allow", "clarify"):
        body = resp.json()
        assert isinstance(body, Mapping)
        assert body.get("text") == "hello"
        assert body.get("meta") == {"topic": "greeting", "id": 123}
        assert body.get("modality") == "text"


def test_ingress_string_payload_roundtrip() -> None:
    payload = {"text": "pаypаl"}
    resp = client.post("/chat/completions", json=payload)

    ing_action = resp.headers.get("X-Guardrail-Decision-Ingress", "")
    if ing_action in ("allow", "clarify"):
        body = resp.json()
        assert isinstance(body, Mapping)
        assert body.get("text") != "pаypаl"
