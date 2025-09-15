from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Any, Dict, List, Optional, TypedDict

import yaml

# ---------------------------------------------------------------------------
# Bindings configuration (existing behaviour)
# ---------------------------------------------------------------------------

_BINDINGS_REPO_ROOT = Path(__file__).resolve().parents[2]
_BINDINGS_CONFIG_DIR = _BINDINGS_REPO_ROOT / "config"
_BINDINGS_CONFIG_PATH = _BINDINGS_CONFIG_DIR / "bindings.yaml"

_BINDINGS_LOCK = RLock()


class Binding(TypedDict):
    tenant: str
    bot: str
    rules_path: str


@dataclass(frozen=True)
class BindingsDoc:
    version: str
    bindings: List[Binding]


def _ensure_bindings_dirs() -> None:
    _BINDINGS_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not _BINDINGS_CONFIG_PATH.exists():
        _BINDINGS_CONFIG_PATH.write_text(
            yaml.safe_dump({"version": "1", "bindings": []}),
            encoding="utf-8",
        )


def load_bindings() -> BindingsDoc:
    with _BINDINGS_LOCK:
        _ensure_bindings_dirs()
        data = yaml.safe_load(_BINDINGS_CONFIG_PATH.read_text(encoding="utf-8")) or {}
        version = str(data.get("version", "1"))
        raw = data.get("bindings") or []
        bindings: List[Binding] = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            tenant = str(item.get("tenant", "")).strip() or "default"
            bot = str(item.get("bot", "")).strip() or "default"
            path = str(item.get("rules_path", "")).strip()
            if path:
                bindings.append({"tenant": tenant, "bot": bot, "rules_path": path})
        return BindingsDoc(version=version, bindings=bindings)


def save_bindings(bindings: List[Binding], version: Optional[str] = None) -> BindingsDoc:
    with _BINDINGS_LOCK:
        _ensure_bindings_dirs()
        doc = {"version": str(version or "1"), "bindings": list(bindings)}
        _BINDINGS_CONFIG_PATH.write_text(
            yaml.safe_dump(doc, sort_keys=False),
            encoding="utf-8",
        )
        return load_bindings()


def upsert_binding(tenant: str, bot: str, rules_path: str) -> BindingsDoc:
    tenant = tenant.strip() or "default"
    bot = bot.strip() or "default"
    bindings = load_bindings().bindings
    updated: List[Binding] = []
    found = False
    for b in bindings:
        if b["tenant"] == tenant and b["bot"] == bot:
            updated.append({"tenant": tenant, "bot": bot, "rules_path": rules_path})
            found = True
        else:
            updated.append(b)
    if not found:
        updated.append({"tenant": tenant, "bot": bot, "rules_path": rules_path})
    return save_bindings(updated)


def delete_binding(tenant: Optional[str] = None, bot: Optional[str] = None) -> BindingsDoc:
    bindings = load_bindings().bindings
    if not tenant and not bot:
        return save_bindings([])
    tenant = (tenant or "").strip()
    bot = (bot or "").strip()
    kept: List[Binding] = []
    for b in bindings:
        if tenant and bot:
            if b["tenant"] == tenant and b["bot"] == bot:
                continue
        elif tenant:
            if b["tenant"] == tenant:
                continue
        elif bot:
            if b["bot"] == bot:
                continue
        kept.append(b)
    return save_bindings(kept)


def resolve_rules_path(tenant: str, bot: str) -> Optional[str]:
    tenant = tenant.strip() or "default"
    bot = bot.strip() or "default"
    doc = load_bindings()
    for b in doc.bindings:
        if b["tenant"] == tenant and b["bot"] == bot:
            return b["rules_path"]
    for b in doc.bindings:
        if b["tenant"] == tenant and b["bot"] == "*":
            return b["rules_path"]
    for b in doc.bindings:
        if b["tenant"] == "*" and b["bot"] == bot:
            return b["rules_path"]
    for b in doc.bindings:
        if b["tenant"] == "*" and b["bot"] == "*":
            return b["rules_path"]
    return None


# ---------------------------------------------------------------------------
# Runtime configuration store
# ---------------------------------------------------------------------------

_BOOL_KEYS = {"lock_enable", "lock_deny_as_execute", "escalation_enabled"}
_INT_KEYS = {
    "escalation_deny_threshold",
    "escalation_window_secs",
    "escalation_cooldown_secs",
}

_BASE_DEFAULTS: Dict[str, Any] = {
    "lock_enable": False,
    "lock_deny_as_execute": False,
    "escalation_enabled": False,
    "escalation_deny_threshold": 3,
    "escalation_window_secs": 300,
    "escalation_cooldown_secs": 900,
}

_CONFIG_KEYS = set(_BASE_DEFAULTS.keys())


def _env_bool(name: str) -> bool | None:
    raw = os.getenv(name)
    if raw is None:
        return None
    s = str(raw).strip()
    if not s:
        return None
    return s.lower() in {"1", "true", "yes", "on"}


def _env_int(name: str) -> int | None:
    raw = os.getenv(name)
    if raw is None:
        return None
    s = str(raw).strip()
    if s == "":
        return None
    try:
        return int(s)
    except Exception:
        return None


def _env_overrides() -> Dict[str, Any]:
    overrides: Dict[str, Any] = {}
    bool_values = {
        "lock_enable": _env_bool("LOCK_ENABLE"),
        "lock_deny_as_execute": _env_bool("LOCK_DENY_AS_EXECUTE"),
        "escalation_enabled": _env_bool("ESCALATION_ENABLED"),
    }
    for key, value in bool_values.items():
        if value is not None:
            overrides[key] = bool(value)
    int_values = {
        "escalation_deny_threshold": _env_int("ESCALATION_DENY_THRESHOLD"),
        "escalation_window_secs": _env_int("ESCALATION_WINDOW_SECS"),
        "escalation_cooldown_secs": _env_int("ESCALATION_COOLDOWN_SECS"),
    }
    for key, value in int_values.items():
        if value is not None:
            overrides[key] = max(1, int(value))
    return overrides

_RUNTIME_LOCK = RLock()


def _config_path() -> str:
    return os.getenv("CONFIG_PATH", "var/config.json")


def _audit_path() -> str:
    return os.getenv("CONFIG_AUDIT_PATH", "var/config_audit.jsonl")


def _ensure_runtime_dirs() -> None:
    cfg_dir = os.path.dirname(_config_path()) or "."
    audit_dir = os.path.dirname(_audit_path()) or "."
    os.makedirs(cfg_dir, exist_ok=True)
    os.makedirs(audit_dir, exist_ok=True)


def _read_runtime_file() -> Dict[str, Any]:
    path = _config_path()
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _atomic_write(path: str, content: str) -> None:
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", dir=directory, delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(content)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_name = tmp.name
    os.replace(tmp_name, path)


def _coerce_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return bool(value)
    s = str(value).strip().lower()
    if s in {"", "0", "false", "no", "off"}:
        return False
    if s in {"1", "true", "yes", "on"}:
        return True
    return default


def _coerce_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except Exception:
        try:
            return int(str(value).strip())
        except Exception:
            return default


def get_config() -> Dict[str, Any]:
    with _RUNTIME_LOCK:
        defaults = dict(_BASE_DEFAULTS)
        stored = _read_runtime_file()
        cfg: Dict[str, Any] = {}
        for key in _CONFIG_KEYS:
            default = defaults[key]
            raw_value = stored.get(key)
            if key in _BOOL_KEYS:
                cfg[key] = _coerce_bool(raw_value, bool(default))
            elif key in _INT_KEYS:
                cfg[key] = max(1, _coerce_int(raw_value, int(default)))
            else:
                cfg[key] = raw_value if raw_value is not None else default
        for key, value in _env_overrides().items():
            if key in _BOOL_KEYS:
                cfg[key] = bool(value)
            elif key in _INT_KEYS:
                cfg[key] = max(1, int(value))
            elif key in _CONFIG_KEYS:
                cfg[key] = value
        return cfg


def set_config(patch: Dict[str, Any], actor: str = "admin") -> Dict[str, Any]:
    with _RUNTIME_LOCK:
        _ensure_runtime_dirs()
        current = get_config()
        filtered_patch: Dict[str, Any] = {}
        for key, value in (patch or {}).items():
            if key not in _CONFIG_KEYS:
                continue
            if key in _BOOL_KEYS:
                filtered_patch[key] = _coerce_bool(value, current[key])
            elif key in _INT_KEYS:
                filtered_patch[key] = max(1, _coerce_int(value, current[key]))
            else:
                filtered_patch[key] = value
        if not filtered_patch:
            return current
        new_cfg = {**current, **filtered_patch}
        _atomic_write(
            _config_path(),
            json.dumps(new_cfg, indent=2, sort_keys=True),
        )
        entry = {
            "ts": int(time.time()),
            "actor": actor,
            "patch": filtered_patch,
            "before": current,
            "after": new_cfg,
        }
        with open(_audit_path(), "a", encoding="utf-8") as audit_file:
            audit_file.write(json.dumps(entry) + "\n")
        return new_cfg
