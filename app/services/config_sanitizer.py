from __future__ import annotations

import os
from math import isfinite
from typing import Optional


def _clean_float(val: Optional[str]) -> Optional[float]:
    if val is None:
        return None
    try:
        f = float(str(val).strip())
        return f if isfinite(f) else None
    except Exception:
        return None


def _clean_int(val: Optional[str]) -> Optional[int]:
    if val is None:
        return None
    try:
        return int(str(val).strip())
    except Exception:
        # allow float-looking strings like "200.0"
        f = _clean_float(val)
        if f is None:
            return None
        try:
            return int(f)
        except Exception:
            return None


def get_verifier_latency_budget_ms() -> Optional[int]:
    """
    Source of truth: env VERIFIER_LATENCY_BUDGET_MS.
    Positive integer → that value.
    Zero/negative/invalid/missing → None (unset = no deadline).
    """
    raw = os.getenv("VERIFIER_LATENCY_BUDGET_MS")
    v = _clean_float(raw)
    if v is None or v <= 0:
        return None
    try:
        return int(v)
    except Exception:
        return None


def get_verifier_retry_budget() -> int:
    """
    Source of truth: env VERIFIER_RETRY_BUDGET.
    Non-negative integer → value; invalid/missing → 0.
    """
    raw = os.getenv("VERIFIER_RETRY_BUDGET")
    v = _clean_int(raw)
    if v is None or v < 0:
        return 0
    return v


def get_stream_guard_lookback_chars(default: int = 256) -> int:
    """
    Source of truth: env STREAM_GUARD_MAX_LOOKBACK_CHARS.
    Non-negative integer; invalid → default; negative → 0.
    """
    raw = os.getenv("STREAM_GUARD_MAX_LOOKBACK_CHARS")
    v = _clean_int(raw)
    if v is None:
        return max(0, int(default))
    return max(0, v)


def get_stream_guard_flush_min_bytes(default: int = 0) -> int:
    """
    Source of truth: env STREAM_GUARD_FLUSH_MIN_BYTES.
    Non-negative integer; invalid → default; negative → 0.
    """
    raw = os.getenv("STREAM_GUARD_FLUSH_MIN_BYTES")
    v = _clean_int(raw)
    if v is None:
        return max(0, int(default))
    return max(0, v)


def get_verifier_sampling_pct() -> float:
    """
    Source of truth: env VERIFIER_SAMPLING_PCT.
    Invalid → 0.0. Always clamped to [0.0, 1.0].
    """
    raw = os.getenv("VERIFIER_SAMPLING_PCT")
    f = _clean_float(raw)
    if f is None:
        return 0.0
    if f < 0.0:
        return 0.0
    if f > 1.0:
        return 1.0
    return f
