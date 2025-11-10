# ruff: noqa: E402
from __future__ import annotations

import pytest

pytest.importorskip("sqlalchemy")

from app.services.decisions import _finalize_decision
from app.services.mitigation_store import reset_for_tests, set_mode


class Dummy:
    def __init__(self, mitigation: str):
        self.mitigation = mitigation


def setup_function():
    reset_for_tests()


def test_finalize_respects_explicit_override():
    set_mode("t", "b", "block")
    decision = Dummy("clarify")
    out = _finalize_decision(decision, tenant="t", bot="b")
    assert out.mitigation == "block"
