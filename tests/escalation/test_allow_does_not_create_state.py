from __future__ import annotations

import importlib

from app.services import escalation as esc


def test_allow_traffic_does_not_create_state(monkeypatch) -> None:
    monkeypatch.setenv("ESCALATION_ENABLED", "true")
    importlib.reload(esc)
    esc._STATE.clear()

    for i in range(500):
        mode, retry = esc.record_and_decide(f"fp-allow-{i}", "allow")
        assert mode == "normal"
        assert retry == 0

    assert (
        len(esc._STATE) == 0
    ), f"Expected no state for allow-only traffic, found {len(esc._STATE)}"

    esc._STATE.clear()
