from __future__ import annotations
import json
import os
import tempfile
import threading
import time
from typing import Any, Dict, Mapping, Optional, TypedDict, Literal

# ----- Public config shape -----

class ConfigDict(TypedDict, total=False):
    lock_enable: bool
    lock_deny_as_execute: bool
    escalation_enabled: bool
    escalation_deny_threshold: int
    escalation_window_secs: int
    escalation_cooldown_secs: int


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


# ----- IO helpers -----

def _ensure_dirs() -> None:
    for path in (_CONFIG_PATH, _AUDIT_PATH):
        d = os.path.dirname(path) or "."
        os.makedirs(d, exist_ok=True)


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


# ----- Coercion -----

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
    if val is None or val == "":
        return None
    try:
        return int(str(val).strip())
    except Exception:
        return None


# ----- Normalization (literal keys so mypy is happy) -----

def normalize_patch(patch: Mapping[str, Any]) -> ConfigDict:
    """
    Return a type-safe patch restricted to known keys.
    Uses literal assignments into ConfigDict to satisfy mypy's TypedDict rules.
    """
    out: ConfigDict = {}

    v_bool = _coerce_bool(patch.get("lock_enable"))
    if v_bool is not None:
        out["lock_enable"] = v_bool

    v_bool = _coerce_bool(patch.get("lock_deny_as_execute"))
    if v_bool is not None:
        out["lock_deny_as_execute"] = v_bool

    v_bool = _coerce_bool(patch.get("escalation_enabled"))
    if v_bool is not None:
        out["escalation_enabled"] = v_bool

    v_int = _coerce_int(patch.get("escalation_deny_threshold"))
    if v_int is not None:
        out["escalation_deny_threshold"] = v_int

    v_int = _coerce_int(patch.get("escalation_window_secs"))
    if v_int is not None:
        out["escalation_window_secs"] = v_int

    v_int = _coerce_int(patch.get("escalation_cooldown_secs"))
    if v_int is not None:
        out["escalation_cooldown_secs"] = v_int

    return out


# ----- Public API -----

def get_config() -> ConfigDict:
    """
    Returns the merged config: defaults overlaid with the persisted file (normalized).
    """
    with _lock:
        data = _read_file()
        normalized = normalize_patch(data)
        return {**_DEFAULTS, **normalized}


def set_config(patch: Mapping[str, Any], actor: str = "admin") -> ConfigDict:
    """
    Applies a patch (bool/int keys only), persists atomically, writes an audit entry,
    and returns the new merged config.
    """
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
