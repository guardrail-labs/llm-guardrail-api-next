from __future__ import annotations

from typing import Any, Dict, Tuple

from fastapi.testclient import TestClient

from app.main import app
from app.routes import guardrail as gr


def test_guardrail_emit_delegates(monkeypatch):
    calls: Dict[str, Any] = {}

    def _fake_emit(payload: Dict[str, Any]) -> None:
        calls["payload"] = payload

    # guardrail module re-exports the service symbol as _emit
    monkeypatch.setattr(gr, "_emit", _fake_emit, raising=False)

    sample = {"ok": True, "n": 1}
    gr.emit_audit_event(sample)

    assert calls.get("payload") == sample


client = TestClient(app)


def test_verifier_block_emitted(monkeypatch):
    calls: Dict[str, Any] = {}

    async def _fake_hv(**_: Any) -> Tuple[str, Dict[str, str]]:
        return "deny", {
            "X-Guardrail-Decision": "deny",
            "X-Guardrail-Decision-Source": "verifier-live",
            "X-Guardrail-Verifier": "prov",
        }

    def _fake_emit(payload: Dict[str, Any]) -> None:
        calls["payload"] = payload

    monkeypatch.setattr(gr, "_maybe_hardened_verify", _fake_hv)
    monkeypatch.setattr(gr, "_emit", _fake_emit, raising=False)

    r = client.post(
        "/guardrail/evaluate",
        json={"text": "hi"},
        headers={"X-Tenant-ID": "t", "X-Bot-ID": "b"},
    )
    assert r.status_code == 200
    v = calls["payload"].get("verifier")
    assert v["provider"] == "prov"
    assert v["decision"] == "deny"
    assert isinstance(v.get("latency_ms"), int)
