from __future__ import annotations

import importlib

from app.services import escalation as esc


def test_deny_creates_state_then_allow_does_not_expand(monkeypatch) -> None:
    monkeypatch.setenv("ESCALATION_ENABLED", "true")
    importlib.reload(esc)
    esc._STATE.clear()

    fp = "fp-test-1"
    mode, retry = esc.record_and_decide(fp, "deny")
    assert mode == "normal"
    assert retry == 0
    assert fp in esc._STATE

    size_after_deny = len(esc._STATE)

    mode2, retry2 = esc.record_and_decide(fp, "allow")
    assert mode2 == "normal"
    assert retry2 == 0
    assert len(esc._STATE) == size_after_deny

    esc._STATE.clear()


def test_allow_purges_after_window(monkeypatch) -> None:
    monkeypatch.setenv("ESCALATION_ENABLED", "true")
    importlib.reload(esc)
    esc._STATE.clear()

    fp = "fp-test-2"
    esc.record_and_decide(fp, "deny")
    assert fp in esc._STATE
    first_ts, _, _ = esc._STATE[fp]

    future = first_ts + esc._window_secs() + 1
    monkeypatch.setattr(esc.time, "time", lambda: future)

    mode, retry = esc.record_and_decide(fp, "allow")
    assert mode == "normal"
    assert retry == 0
    assert fp not in esc._STATE

    esc._STATE.clear()
