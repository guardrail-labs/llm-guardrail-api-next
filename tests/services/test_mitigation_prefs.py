from __future__ import annotations

import pytest

from app.services import mitigation_prefs as mp


@pytest.fixture(autouse=True)
def _reset_store() -> None:
    mp._reset_for_tests()


def test_validate_and_persist() -> None:
    mp.set_mode("t1", "b1", "block")
    assert mp.get_mode("t1", "b1") == "block"
    with pytest.raises(ValueError):
        mp.set_mode("t1", "b1", "nope")  # type: ignore[arg-type]


def test_resolve_default_when_none() -> None:
    mode, source = mp.resolve_mode(
        tenant="tX",
        bot="bX",
        policy_default="clarify",
    )
    assert mode == "clarify"
    assert source == "default"


def test_resolve_explicit_wins() -> None:
    mp.set_mode("t2", "b2", "redact")
    mode, source = mp.resolve_mode(
        tenant="t2",
        bot="b2",
        policy_default="clarify",
    )
    assert mode == "redact"
    assert source == "explicit"
