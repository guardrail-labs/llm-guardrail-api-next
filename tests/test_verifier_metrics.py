from __future__ import annotations

import importlib
import os
from types import SimpleNamespace

from fastapi.testclient import TestClient


def _client_with_verifier(monkeypatch) -> TestClient:
    # Enable verifier before importing app
    os.environ["VERIFIER_ENABLED"] = "1"
    os.environ["GUARDRAIL_DISABLE_AUTH"] = "1"  # legacy guard skips key in some routes

    import app.services.verifier_client as vcli

    # Mock provider response: clarify
    def _fake_call(_inp):
        return SimpleNamespace(provider="mock", decision="clarify", latency_ms=12)

    monkeypatch.setattr(vcli, "call_verifier", _fake_call, raising=True)

    import app.main as main
    importlib.reload(main)
    return TestClient(main.app)


def test_verifier_debug_and_metric(monkeypatch):
    c = _client_with_verifier(monkeypatch)

    # Trigger ingress evaluate with debug so verifier snippet is returned
    r = c.post("/guardrail/evaluate", json={"text": "hello"}, headers={"X-Debug": "1"})
    assert r.status_code == 200
    body = r.json()
    assert body["action"] == "clarify"  # forced by mocked verifier
    assert "debug" in body and "verifier" in body["debug"]
    v = body["debug"]["verifier"]
    assert v.get("provider") == "mock"
    assert v.get("decision") == "clarify"

    # Metrics should include verifier outcome counter (exposed by prometheus_client)
    m = c.get("/metrics")
    assert m.status_code == 200
    text = m.text
    assert "guardrail_verifier_outcome_total" in text
    # label presence check (exact line format depends on prometheus_client)
    assert 'verifier="mock"' in text and 'outcome="clarify"' in text
