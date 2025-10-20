from __future__ import annotations

import math
import time
from typing import Dict, List


def hdr_percentiles(latencies_ms: List[float]) -> Dict[str, float]:
    """Return p50/p95/p99 for a list of ms latencies."""
    if not latencies_ms:
        return {"p50": 0.0, "p95": 0.0, "p99": 0.0}
    xs = sorted(latencies_ms)

    def pct(p: float) -> float:
        k = max(0, min(len(xs) - 1, int(math.ceil(p * len(xs)) - 1)))
        return float(xs[k])

    return {"p50": pct(0.50), "p95": pct(0.95), "p99": pct(0.99)}


def now_ts() -> str:
    return time.strftime("%Y%m%d-%H%M%S")


def merge_counts(a: Dict[str, int], b: Dict[str, int]) -> Dict[str, int]:
    out = dict(a)
    for k, v in b.items():
        out[k] = out.get(k, 0) + v
    return out
