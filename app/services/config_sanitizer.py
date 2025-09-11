from __future__ import annotations

import os
from math import isfinite
from typing import Optional


def _from_runtime_flags(name: str) -> Optional[str]:
    """Best effort read from runtime flags without importing at module import time."""
    try:
        from app.services import runtime_flags as rf  # local to avoid cycles
    except Exception:
        return None
    try:
        store = getattr(rf, "_STORE", {})
        if name not in store:
            return None
        v = rf.get(name)  # type: ignore[no-redef]
    except Exception:
        return None
    if v is None:
        return None
    s = str(v).strip()
    return s if s else None


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
    Positive integer → that value.
    Zero/negative/invalid/missing → None (unset = no deadline).
    """
    raw = _from_runtime_flags("verifier_latency_budget_ms")
    if raw is None:
        raw = os.getenv("VERIFIER_LATENCY_BUDGET_MS")
    v = _clean_float(raw)
    if v is None or v <= 0:
        return None
    try:
        return int(v)
    except Exception:
        return None


def get_verifier_retry_budget() -> int:
    """Non-negative integer, invalid → 0."""
    raw = _from_runtime_flags("verifier_retry_budget")
    if raw is None:
        raw = os.getenv("VERIFIER_RETRY_BUDGET")
    v = _clean_int(raw)
    if v is None or v < 0:
        return 0
    return v


def get_stream_guard_lookback_chars(default: int = 256) -> int:
    """Non-negative integer; invalid → default; negative → 0."""
    raw = _from_runtime_flags("stream_guard_max_lookback_chars")
    if raw is None:
        raw = os.getenv("STREAM_GUARD_MAX_LOOKBACK_CHARS")
    v = _clean_int(raw)
    if v is None:
        return max(0, int(default))
    return max(0, v)


def get_stream_guard_flush_min_bytes(default: int = 0) -> int:
    """Non-negative integer; invalid → default; negative → 0."""
    raw = _from_runtime_flags("stream_guard_flush_min_bytes")
    if raw is None:
        raw = os.getenv("STREAM_GUARD_FLUSH_MIN_BYTES")
    v = _clean_int(raw)
    if v is None:
        return max(0, int(default))
    return max(0, v)


def get_verifier_sampling_pct() -> float:
    """
    verifier_sampling_pct: prefer runtime flag, else env VERIFIER_SAMPLING_PCT.
    Invalid → 0.0. Always clamped to [0.0, 1.0].
    """
    raw = _from_runtime_flags("verifier_sampling_pct")
    if raw is None:
        raw = os.getenv("VERIFIER_SAMPLING_PCT")
    f = _clean_float(raw)
    if f is None:
        return 0.0
    if f < 0.0:
        return 0.0
    if f > 1.0:
        return 1.0
    return f
