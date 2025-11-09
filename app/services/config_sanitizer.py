from __future__ import annotations

import math
import os
from dataclasses import dataclass
from typing import Optional, Tuple

# ---------- Internal utilities ----------


def _coerce_num(raw: str | float | int) -> Optional[float]:
    """Best-effort numeric coercion. Returns None on failure or NaN.

    Accepts: numeric types and numeric-ish strings (e.g., "1", "1.5").
    """
    try:
        if isinstance(raw, (int, float)):
            val = float(raw)
        else:
            # Strip whitespace; tolerate trailing unit markers for ms handler
            s = str(raw).strip()
            # Defer unit parsing to caller; try plain float first
            val = float(s)
        if math.isnan(val) or math.isinf(val):
            return None
        return val
    except Exception:
        return None


def _parse_ms(raw: str | float | int) -> Optional[float]:
    """Parse milliseconds from numeric or strings like "200", "200.5", "200ms".

    Returns float milliseconds (not rounded). None if invalid or non-positive.
    """
    if isinstance(raw, (int, float)):
        ms = float(raw)
    else:
        s = str(raw).strip().lower()
        if s.endswith("ms"):
            s = s[:-2].strip()
        num = _coerce_num(s)
        if num is None:
            return None
        ms = num
    if ms <= 0:
        return None
    return ms


# ---------- Public helpers (generic) ----------


def get_bool(env: str, *, default: bool = False) -> bool:
    """Parse boolean-ish env var; supports: 1/0, true/false, yes/no, on/off.
    Missing => default.
    """
    val = os.getenv(env)
    if val is None:
        return default
    s = val.strip().lower()
    if s in {"1", "true", "t", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "f", "no", "n", "off"}:
        return False
    return default


def get_int(
    env: str,
    *,
    default: int = 0,
    min_value: Optional[int] = None,
    max_value: Optional[int] = None,
) -> int:
    """Parse int with optional clamps; invalid/missing => default."""
    raw = os.getenv(env)
    if raw is None:
        return default
    try:
        val = int(float(str(raw).strip()))
    except Exception:
        return default
    if min_value is not None:
        val = max(min_value, val)
    if max_value is not None:
        val = min(max_value, val)
    return val


def get_float(
    env: str,
    *,
    default: float = 0.0,
    min_value: Optional[float] = None,
    max_value: Optional[float] = None,
) -> float:
    """Parse float with optional clamps and NaN handling; invalid/missing => default."""
    raw = os.getenv(env)
    if raw is None:
        return default
    num = _coerce_num(raw)
    if num is None:
        return default
    val = num
    if min_value is not None:
        val = max(min_value, val)
    if max_value is not None:
        val = min(max_value, val)
    return val


# ---------- Public helpers (project-specific) ----------


def get_verifier_latency_budget_ms() -> Optional[int]:
    """Read VERIFIER_LATENCY_BUDGET_MS as milliseconds.

    Accepts numeric or string with optional trailing "ms".
    Missing/NaN/≤0 => None.
    Rounds down to int milliseconds if valid.
    """
    raw = os.getenv("VERIFIER_LATENCY_BUDGET_MS")
    if raw is None or str(raw).strip() == "":
        return None
    ms = _parse_ms(raw)
    if ms is None:
        return None
    return int(ms)


def get_verifier_sampling_pct() -> float:
    """Read VERIFIER_SAMPLING_PCT.

    Clamps to [0.0, 1.0]. Bad/missing input => 0.0.
    """
    pct = get_float("VERIFIER_SAMPLING_PCT", default=0.0)
    # Clamp to [0, 1]
    if pct < 0.0:
        return 0.0
    if pct > 1.0:
        return 1.0
    return pct


def get_verifier_retry_budget() -> int:
    """Read VERIFIER_RETRY_BUDGET; invalid/missing → 0."""
    return get_int("VERIFIER_RETRY_BUDGET", default=0, min_value=0)


# Optional: snapshot for a single boot log line
@dataclass(frozen=True)
class ConfigSnapshot:
    verifier_latency_budget_ms: Optional[int]
    verifier_sampling_pct: float

    @classmethod
    def capture(cls) -> "ConfigSnapshot":
        return cls(
            verifier_latency_budget_ms=get_verifier_latency_budget_ms(),
            verifier_sampling_pct=get_verifier_sampling_pct(),
        )

    def as_kv(self) -> Tuple[Tuple[str, str], ...]:
        lat = (
            "None"
            if self.verifier_latency_budget_ms is None
            else str(self.verifier_latency_budget_ms)
        )
        return (
            ("VERIFIER_LATENCY_BUDGET_MS", lat),
            ("VERIFIER_SAMPLING_PCT", f"{self.verifier_sampling_pct:.3f}"),
        )
