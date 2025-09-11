from __future__ import annotations

import os
from importlib import reload

import app.services.config_sanitizer as cs


def _clear_env(*names: str) -> None:
    for n in names:
        os.environ.pop(n, None)


def test_latency_budget_parsing_unset() -> None:
    _clear_env("VERIFIER_LATENCY_BUDGET_MS")
    reload(cs)
    assert cs.get_verifier_latency_budget_ms() is None


def test_latency_budget_parsing_empty() -> None:
    os.environ["VERIFIER_LATENCY_BUDGET_MS"] = ""
    assert cs.get_verifier_latency_budget_ms() is None


def test_latency_budget_parsing_plain_number() -> None:
    os.environ["VERIFIER_LATENCY_BUDGET_MS"] = "250"
    assert cs.get_verifier_latency_budget_ms() == 250


def test_latency_budget_parsing_float_string() -> None:
    os.environ["VERIFIER_LATENCY_BUDGET_MS"] = "250.7"
    assert cs.get_verifier_latency_budget_ms() == 250  # floor


def test_latency_budget_parsing_with_unit_ms() -> None:
    os.environ["VERIFIER_LATENCY_BUDGET_MS"] = "200ms"
    assert cs.get_verifier_latency_budget_ms() == 200


def test_latency_budget_parsing_zero_negative() -> None:
    os.environ["VERIFIER_LATENCY_BUDGET_MS"] = "0"
    assert cs.get_verifier_latency_budget_ms() is None
    os.environ["VERIFIER_LATENCY_BUDGET_MS"] = "-1"
    assert cs.get_verifier_latency_budget_ms() is None


def test_latency_budget_parsing_alpha() -> None:
    os.environ["VERIFIER_LATENCY_BUDGET_MS"] = "abc"
    assert cs.get_verifier_latency_budget_ms() is None


def test_sampling_pct_unset_defaults_to_zero() -> None:
    _clear_env("VERIFIER_SAMPLING_PCT")
    assert cs.get_verifier_sampling_pct() == 0.0


def test_sampling_pct_basic_values() -> None:
    os.environ["VERIFIER_SAMPLING_PCT"] = "0.25"
    assert cs.get_verifier_sampling_pct() == 0.25
    os.environ["VERIFIER_SAMPLING_PCT"] = "1.0"
    assert cs.get_verifier_sampling_pct() == 1.0


def test_sampling_pct_clamps() -> None:
    os.environ["VERIFIER_SAMPLING_PCT"] = "-0.5"
    assert cs.get_verifier_sampling_pct() == 0.0
    os.environ["VERIFIER_SAMPLING_PCT"] = "2.0"
    assert cs.get_verifier_sampling_pct() == 1.0


def test_sampling_pct_alpha_returns_zero() -> None:
    os.environ["VERIFIER_SAMPLING_PCT"] = "abc"
    assert cs.get_verifier_sampling_pct() == 0.0
