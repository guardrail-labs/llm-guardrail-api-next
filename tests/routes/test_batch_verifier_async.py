from __future__ import annotations

import importlib

from fastapi.testclient import TestClient


def _client() -> TestClient:
    import app.main as main
    import app.telemetry.metrics as metrics

    importlib.reload(metrics)
    importlib.reload(main)
    return TestClient(main.app)


def test_batch_verifier_async(monkeypatch) -> None:
    import app.services.verifier as verifier

    async def fake_assess(self, text: str, meta=None):
        return verifier.Verdict.SAFE, "stub"

    monkeypatch.setattr(verifier, "verifier_enabled", lambda: True)
    monkeypatch.setattr(verifier, "load_providers_order", lambda: ["stub"])
    monkeypatch.setattr(verifier.Verifier, "assess_intent", fake_assess)

    c = _client()
    headers = {
        "X-API-Key": "k",
        "X-Tenant-ID": "t",
        "X-Bot-ID": "b",
        "Content-Type": "application/json",
        "X-Force-Unclear": "1",
    }
    r = c.post("/guardrail/batch_evaluate", json={"items": [{"text": "hi"}]}, headers=headers)
    assert r.status_code == 200
    data = r.json()
    assert data["count"] == 1
    assert isinstance(data["items"], list)

