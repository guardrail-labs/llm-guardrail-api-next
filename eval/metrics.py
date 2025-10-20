from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, Tuple


@dataclass(frozen=True)
class PRF:
    tp: int
    fp: int
    fn: int
    prec: float
    rec: float
    f1: float


def prf(tp: int, fp: int, fn: int) -> PRF:
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) else 0.0
    return PRF(tp=tp, fp=fp, fn=fn, prec=p, rec=r, f1=f1)


def aggregate_by_cat(rows: Iterable[Tuple[str, int, int]]) -> Dict[str, PRF]:
    """Input rows: (cat, label, pred) where 1=positive, 0=negative."""
    stats: Dict[str, Tuple[int, int, int]] = {}
    for cat, label, pred in rows:
        tp, fp, fn = stats.get(cat, (0, 0, 0))
        if label == 1 and pred == 1:
            tp += 1
        elif label == 0 and pred == 1:
            fp += 1
        elif label == 1 and pred == 0:
            fn += 1
        stats[cat] = (tp, fp, fn)
    return {k: prf(*v) for k, v in stats.items()}
