from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_healthz_returns_flags_and_policy_version() -> None:
    r = client.get("/healthz")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert isinstance(body["policy_version"], str)
    feats = body.get("features", {})
    assert set(feats) == {
        "pdf_detector",
        "docx_detector",
        "image_safe_transform",
    }
    assert all(isinstance(v, bool) for v in feats.values())
