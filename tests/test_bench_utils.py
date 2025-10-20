from __future__ import annotations

from bench.utils import hdr_percentiles, merge_counts


def test_hdr_percentiles_basic() -> None:
    xs = [1.0, 2.0, 3.0, 4.0]
    pct = hdr_percentiles(xs)
    assert pct["p50"] >= 2.0
    assert pct["p99"] <= 4.0


def test_merge_counts() -> None:
    a = {"200": 10, "ERR": 1}
    b = {"200": 5, "429": 2}
    out = merge_counts(a, b)
    assert out["200"] == 15
    assert out["ERR"] == 1
    assert out["429"] == 2
