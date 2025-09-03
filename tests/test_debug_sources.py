from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_debug_sources_shape_ingress_text() -> None:
    r = client.post(
        "/guardrail/evaluate",
        json={"text": "Contact me at jane@example.com"},
        headers={"X-Debug": "1"},
    )
    assert r.status_code == 200
    body = r.json()

    dbg = body.get("debug")
    assert dbg and isinstance(dbg.get("sources"), list)
    src = dbg["sources"][0]
    assert src["origin"] == "ingress"
    assert src["modality"] == "text"
    assert src["mime_type"] == "text/plain"
    assert "sha256" in src
    assert isinstance(src.get("rule_hits"), dict)
    assert isinstance(src.get("redactions"), list)


def test_debug_sources_shape_egress_text() -> None:
    r = client.post(
        "/guardrail/egress_evaluate",
        json={"text": "Call 555-123-4567"},
        headers={"X-Debug": "1"},
    )
    assert r.status_code == 200
    body = r.json()

    dbg = body.get("debug")
    assert dbg and isinstance(dbg.get("sources"), list)
    assert any(s["origin"] == "egress" for s in dbg["sources"])
