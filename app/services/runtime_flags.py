from __future__ import annotations

import os
from threading import RLock
from typing import Any, Dict, List, Tuple

# Default flag values
_DEFAULTS: Dict[str, Any] = {
    "verifier_sampling_pct": 0.0,
    "verifier_latency_budget_ms": 250,
    "verifier_max_retries": 1,
    "verifier_retry_backoff_ms": 50,
    "verifier_retry_jitter_ms": 50,
    "verifier_error_fallback": "allow",
    "policy_default_injection_action": "block",
    "pdf_detector_enabled": True,
    "docx_detector_enabled": True,
    "image_safe_transform_enabled": True,
    "threat_feed_enabled": False,
    "max_prompt_chars": 0,
    "stream_egress_enabled": True,
    "stream_guard_max_lookback_chars": 1024,
    "stream_guard_flush_min_bytes": 0,
    "stream_guard_deny_on_private_key": True,
}

# Mapping of flag name -> environment variable
_ENV_MAP: Dict[str, str] = {
    "verifier_sampling_pct": "VERIFIER_SAMPLING_PCT",
    "verifier_latency_budget_ms": "VERIFIER_LATENCY_BUDGET_MS",
    "verifier_max_retries": "VERIFIER_MAX_RETRIES",
    "verifier_retry_backoff_ms": "VERIFIER_RETRY_BACKOFF_MS",
    "verifier_retry_jitter_ms": "VERIFIER_RETRY_JITTER_MS",
    "verifier_error_fallback": "VERIFIER_ERROR_FALLBACK",
    "policy_default_injection_action": "POLICY_DEFAULT_INJECTION_ACTION",
    "pdf_detector_enabled": "PDF_DETECTOR_ENABLED",
    "docx_detector_enabled": "DOCX_DETECTOR_ENABLED",
    "image_safe_transform_enabled": "IMAGE_SAFE_TRANSFORM_ENABLED",
    "threat_feed_enabled": "THREAT_FEED_ENABLED",
    "max_prompt_chars": "MAX_PROMPT_CHARS",
    "stream_egress_enabled": "STREAM_EGRESS_ENABLED",
    "stream_guard_max_lookback_chars": "STREAM_GUARD_MAX_LOOKBACK_CHARS",
    "stream_guard_flush_min_bytes": "STREAM_GUARD_FLUSH_MIN_BYTES",
    "stream_guard_deny_on_private_key": "STREAM_GUARD_DENY_ON_PRIVATE_KEY",
}

_LOCK = RLock()
_STORE: Dict[str, Any] = {}


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


def _err(msg: str) -> Tuple[None, str]:
    return None, msg


def _coerce_float_in_range(val: Any, *, lo: float, hi: float) -> Tuple[Any, str | None]:
    try:
        f = float(val)
    except Exception:
        return _err("must be a float")
    if f < lo or f > hi:
        return _err(f"must be between {lo} and {hi}")
    return f, None


def _coerce_int_in_range(val: Any, *, lo: int, hi: int) -> Tuple[Any, str | None]:
    try:
        i = int(val)
    except Exception:
        return _err("must be an int")
    if i < lo or i > hi:
        return _err(f"must be between {lo} and {hi}")
    return i, None


def _coerce_bool(val: Any) -> Tuple[Any, str | None]:
    if isinstance(val, bool):
        return val, None
    if isinstance(val, str):
        if val.strip().lower() in {"1", "true", "yes", "on"}:
            return True, None
        if val.strip().lower() in {"0", "false", "no", "off"}:
            return False, None
    if isinstance(val, (int, float)):
        return bool(val), None
    return _err("must be a bool")


def _coerce_choice(
    val: Any, choices: List[str], *, alias: Dict[str, str] | None = None
) -> Tuple[Any, str | None]:
    if not isinstance(val, str):
        return _err("must be a string")
    v = val.strip().lower()
    if alias and v in alias:
        v = alias[v]
    if v not in choices:
        return _err(f"must be one of {','.join(choices)}")
    return v, None


_VALIDATORS = {
    "verifier_sampling_pct": lambda v: _coerce_float_in_range(v, lo=0.0, hi=1.0),
    "verifier_latency_budget_ms": lambda v: _coerce_int_in_range(v, lo=50, hi=1_000_000),
    "verifier_max_retries": lambda v: _coerce_int_in_range(v, lo=0, hi=3),
    "verifier_retry_backoff_ms": lambda v: _coerce_int_in_range(v, lo=0, hi=2000),
    "verifier_retry_jitter_ms": lambda v: _coerce_int_in_range(v, lo=0, hi=2000),
    "verifier_error_fallback": lambda v: _coerce_choice(v, ["allow", "deny", "clarify"]),
    "policy_default_injection_action": lambda v: _coerce_choice(
        v,
        ["allow", "block", "clarify"],
        alias={"deny": "block"},
    ),
    "pdf_detector_enabled": _coerce_bool,
    "docx_detector_enabled": _coerce_bool,
    "image_safe_transform_enabled": _coerce_bool,
    "threat_feed_enabled": _coerce_bool,
    "max_prompt_chars": lambda v: _coerce_int_in_range(v, lo=0, hi=10_000_000),
    "stream_egress_enabled": _coerce_bool,
    "stream_guard_max_lookback_chars": lambda v: _coerce_int_in_range(v, lo=0, hi=1_000_000),
    "stream_guard_flush_min_bytes": lambda v: _coerce_int_in_range(v, lo=0, hi=1_000_000),
    "stream_guard_deny_on_private_key": _coerce_bool,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get(name: str) -> Any:
    if name in _STORE:
        return _STORE[name]
    if name not in _DEFAULTS:
        raise KeyError(name)
    env = _ENV_MAP.get(name)
    if env:
        raw = os.getenv(env)
        if raw not in (None, ""):
            val, err = _VALIDATORS[name](raw)
            if err is None:
                return val
    return _DEFAULTS[name]


def set_many(patch: Dict[str, Any]) -> Tuple[List[str], Dict[str, str]]:
    updated: List[str] = []
    errors: Dict[str, str] = {}
    with _LOCK:
        for k, v in patch.items():
            if k not in _DEFAULTS:
                errors[k] = "unknown_flag"
                continue
            val, err = _VALIDATORS[k](v)
            if err is not None:
                errors[k] = err
                continue
            _STORE[k] = val
            updated.append(k)
    return updated, errors


def effective() -> Dict[str, Any]:
    return {k: get(k) for k in _DEFAULTS.keys()}


def reset() -> None:
    with _LOCK:
        _STORE.clear()


def stream_egress_enabled() -> bool:
    return bool(get("stream_egress_enabled"))


def stream_guard_max_lookback_chars() -> int:
    return int(get("stream_guard_max_lookback_chars"))


def stream_guard_flush_min_bytes() -> int:
    return int(get("stream_guard_flush_min_bytes"))


def stream_guard_deny_on_private_key() -> bool:
    return bool(get("stream_guard_deny_on_private_key"))
