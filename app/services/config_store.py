# app/services/config_store.py
from __future__ import annotations
import json, os, threading, time, tempfile
from typing import Any, Dict, Mapping, Optional, Tuple, TypedDict, Union

# ----- Types & schema -----

BoolKey = Union[
    # keep these in sync with docs/admin page keys
    Literal["lock_enable"], Literal["lock_deny_as_execute"],
    Literal["escalation_enabled"],
]
IntKey = Union[
    Literal["escalation_deny_threshold"], Literal["escalation_window_secs"], Literal["escalation_cooldown_secs"]
]

class ConfigDict(TypedDict, total=False):
    lock_enable: bool
    lock_deny_as_execute: bool
    escalation_enabled: bool
    escalation_deny_threshold: int
    escalation_window_secs: int
    escalation_cooldown_secs: int

BOOL_KEYS: set[str] = {
    "lock_enable", "lock_deny_as_execute", "escalation_enabled",
}
INT_KEYS: set[str] = {
    "escalation_deny_threshold", "escalation_window_secs", "escalation_cooldown_secs",
}

_DEFAULTS: ConfigDict = {
    "lock_enable": False,
    "lock_deny_as_execute": False,
    "escalation_enabled": False,
    "escalation_deny_threshold": 3,
    "escalation_window_secs": 300,
    "escalation_cooldown_secs": 900,
}

_CONFIG_PATH = os.getenv("CONFIG_PATH", "var/config.json")
_AUDIT_PATH = os.getenv("CONFIG_AUDIT_PATH", "var/config_audit.jsonl")
_lock = threading.RLock()

def _ensure_dirs() -> None:
    d = os.path.dirname(_CONFIG_PATH) or "."
    os.makedirs(d, exist_ok=True)
    d2 = os.path.dirname(_AUDIT_PATH) or "."
    os.makedirs(d2, exist_ok=True)

def _read_file() -> Dict[str, Any]:
    if not os.path.exists(_CONFIG_PATH):
        return {}
    with open(_CONFIG_PATH, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

def _atomic_write(path: str, content: str) -> None:
    d = os.path.dirname(path) or "."
    with tempfile.NamedTemporaryFile("w", dir=d, delete=False, encoding="utf-8") as tmp:
        tmp.write(content)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_name = tmp.name
    os.replace(tmp_name, path)

def _coerce_bool(val: Any) -> Optional[bool]:
    if isinstance(val, bool):
        return val
    if val is None:
        return None
    s = str(val).strip().lower()
    if s in ("true", "1", "yes", "on"):
        return True
    if s in ("false", "0", "no", "off"):
        return False
    return None

def _coerce_int(val: Any) -> Optional[int]:
    if isinstance(val, int):
        return val
    if val is None:
        return None
    try:
        return int(str(val).strip())
    except Exception:
        return None

def normalize_patch(patch: Mapping[str, Any]) -> ConfigDict:
    """Return a type-safe patch restricted to known keys."""
    out: ConfigDict = {}
    for k, v in patch.items():
        if k in BOOL_KEYS:
            b = _coerce_bool(v)
            if b is not None:
                out[k] = b  # type: ignore[typeddict-item]
        elif k in INT_KEYS:
            i = _coerce_int(v)
            if i is not None:
                out[k] = i  # type: ignore[typeddict-item]
        # silently ignore unknown keys
    return out

def get_config() -> ConfigDict:
    with _lock:
        data = _read_file()
        normalized = normalize_patch(data)
        return {**_DEFAULTS, **normalized}

def set_config(patch: Mapping[str, Any], actor: str = "admin") -> ConfigDict:
    with _lock:
        _ensure_dirs()
        current = get_config()
        typed_patch = normalize_patch(patch)
        new_cfg: ConfigDict = {**current, **typed_patch}
        _atomic_write(_CONFIG_PATH, json.dumps(new_cfg, indent=2, sort_keys=True))
        entry = {
            "ts": int(time.time()),
            "actor": actor,
            "patch": typed_patch,
            "before": current,
            "after": new_cfg,
        }
        with open(_AUDIT_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        return new_cfg
