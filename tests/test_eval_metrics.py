from __future__ import annotations

from eval.metrics import aggregate_by_cat, prf


def test_prf_math() -> None:
    result = prf(tp=8, fp=2, fn=2)
    assert round(result.prec, 4) == 0.8
    assert round(result.rec, 4) == 0.8
    assert round(result.f1, 4) == 0.8


def test_aggregate_by_cat_counts() -> None:
    rows = [
        ("injection", 1, 1),
        ("injection", 0, 1),
        ("injection", 1, 0),
        ("unicode", 1, 1),
        ("unicode", 0, 0),
    ]
    per = aggregate_by_cat(rows)
    injection = per["injection"]
    unicode_cat = per["unicode"]
    assert (injection.tp, injection.fp, injection.fn) == (1, 1, 1)
    assert (unicode_cat.tp, unicode_cat.fp, unicode_cat.fn) == (1, 0, 0)
