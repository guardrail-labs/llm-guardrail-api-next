# ruff: noqa: E402
from __future__ import annotations

import pytest

pytest.importorskip("sqlalchemy")

from app.observability.metrics import mitigation_override_counter  # noqa: E402
from app.services.mitigation_prefs import _STORE, set_mode  # noqa: E402


class DummyResult:
    def __init__(self, mitigation: str) -> None:
        self.mitigation = mitigation


def _counter_value() -> float:
    value = getattr(mitigation_override_counter, "_value", None)
    if value is None:
        return 0.0
    current = value.get()
    return float(current)


def setup_function() -> None:
    _STORE.clear()


def test_override_changes_outcome_increments() -> None:
    set_mode("t1", "b1", "block")
    from app.services.decisions import _finalize_decision

    start = _counter_value()
    result = _finalize_decision(DummyResult("clarify"), tenant="t1", bot="b1")
    assert result.mitigation == "block"
    assert _counter_value() == start + 1


def test_override_same_as_default_no_increment() -> None:
    set_mode("t2", "b2", "clarify")
    from app.services.decisions import _finalize_decision

    start = _counter_value()
    result = _finalize_decision(DummyResult("clarify"), tenant="t2", bot="b2")
    assert result.mitigation == "clarify"
    assert _counter_value() == start
