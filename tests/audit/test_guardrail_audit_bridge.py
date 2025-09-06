from __future__ import annotations

from typing import Any, Dict

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

