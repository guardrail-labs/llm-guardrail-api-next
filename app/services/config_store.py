from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Any, Dict, List, Mapping, Optional, TypedDict, cast

import yaml

# File lives at repo_root/config/bindings.yaml
# app/services -> app -> repo_root
_REPO_ROOT = Path(__file__).resolve().parents[2]
_CONFIG_DIR = _REPO_ROOT / "config"
_CONFIG_PATH = _CONFIG_DIR / "bindings.yaml"
_ADMIN_CONFIG_PATH = _CONFIG_DIR / "admin_config.yaml"

_LOCK = RLock()


class Binding(TypedDict):
    tenant: str
    bot: str
    rules_path: str


@dataclass(frozen=True)
class BindingsDoc:
    version: str
    bindings: List[Binding]


def _ensure_dirs() -> None:
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not _CONFIG_PATH.exists():
        _CONFIG_PATH.write_text(yaml.safe_dump({"version": "1", "bindings": []}), encoding="utf-8")
    if not _ADMIN_CONFIG_PATH.exists():
        _ADMIN_CONFIG_PATH.write_text(yaml.safe_dump({}, sort_keys=False), encoding="utf-8")


def load_bindings() -> BindingsDoc:
    with _LOCK:
        _ensure_dirs()
        data = yaml.safe_load(_CONFIG_PATH.read_text(encoding="utf-8")) or {}
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
    with _LOCK:
        _ensure_dirs()
        doc = {"version": str(version or "1"), "bindings": list(bindings)}
        _CONFIG_PATH.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
        return load_bindings()


def upsert_binding(tenant: str, bot: str, rules_path: str) -> BindingsDoc:
    tenant = tenant.strip() or "default"
    bot = bot.strip() or "default"
    bindings = load_bindings().bindings
    # replace if exists
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
        # clear all
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
    """
    Exact match first; then wildcard '*' for tenant and/or bot.
    Return first matching rules_path, else None.
    """
    tenant = tenant.strip() or "default"
    bot = bot.strip() or "default"
    doc = load_bindings()
    # exact
    for b in doc.bindings:
        if b["tenant"] == tenant and b["bot"] == bot:
            return b["rules_path"]
    # tenant + wildcard bot
    for b in doc.bindings:
        if b["tenant"] == tenant and b["bot"] == "*":
            return b["rules_path"]
    # wildcard tenant + bot
    for b in doc.bindings:
        if b["tenant"] == "*" and b["bot"] == bot:
            return b["rules_path"]
    # global wildcard
    for b in doc.bindings:
        if b["tenant"] == "*" and b["bot"] == "*":
            return b["rules_path"]
    return None


class ConfigDict(TypedDict, total=False):
    shadow_enable: bool
    shadow_policy_path: str
    shadow_timeout_ms: int
    shadow_sample_rate: float
    webhook_enable: bool
    webhook_url: str
    webhook_secret: str
    webhook_timeout_ms: int
    webhook_max_retries: int
    webhook_backoff_ms: int
    webhook_cb_error_threshold: int
    webhook_cb_window: int
    webhook_cb_cooldown_sec: int
    webhook_backoff_cap_ms: int
    webhook_allow_insecure_tls: bool
    webhook_allowlist_host: str


_CONFIG_DEFAULTS: ConfigDict = {
    "shadow_enable": False,
    "shadow_policy_path": "",
    "shadow_timeout_ms": 100,
    "shadow_sample_rate": 1.0,
    "webhook_enable": False,
    "webhook_url": "",
    "webhook_secret": "",
    "webhook_timeout_ms": 2000,
    "webhook_max_retries": 5,
    "webhook_backoff_ms": 500,
    "webhook_cb_error_threshold": 8,
    "webhook_cb_window": 30,
    "webhook_cb_cooldown_sec": 60,
    "webhook_backoff_cap_ms": 10_000,
    "webhook_allow_insecure_tls": False,
    "webhook_allowlist_host": "",
}

_CONFIG_ENV_MAP: Dict[str, str] = {
    "shadow_enable": "SHADOW_ENABLE",
    "shadow_policy_path": "SHADOW_POLICY_PATH",
    "shadow_timeout_ms": "SHADOW_TIMEOUT_MS",
    "shadow_sample_rate": "SHADOW_SAMPLE_RATE",
    "webhook_enable": "WEBHOOK_ENABLE",
    "webhook_url": "WEBHOOK_URL",
    "webhook_secret": "WEBHOOK_SECRET",
    "webhook_timeout_ms": "WEBHOOK_TIMEOUT_MS",
    "webhook_max_retries": "WEBHOOK_MAX_RETRIES",
    "webhook_backoff_ms": "WEBHOOK_BACKOFF_MS",
    "webhook_cb_error_threshold": "WEBHOOK_CB_ERROR_THRESHOLD",
    "webhook_cb_window": "WEBHOOK_CB_WINDOW",
    "webhook_cb_cooldown_sec": "WEBHOOK_CB_COOLDOWN_SEC",
    "webhook_backoff_cap_ms": "WEBHOOK_BACKOFF_CAP_MS",
    "webhook_allow_insecure_tls": "WEBHOOK_ALLOW_INSECURE_TLS",
    "webhook_allowlist_host": "WEBHOOK_ALLOWLIST_HOST",
}

_CONFIG_STATE: Dict[str, Any] = {}
_CONFIG_LOADED = False


def _config_audit_path() -> Path:
    raw = os.getenv("CONFIG_AUDIT_PATH")
    if raw:
        return Path(raw)
    return _REPO_ROOT / "var" / "config_audit.jsonl"


def get_config_audit_path() -> Path:
    """Return the configured audit log path for admin config writes."""

    return _config_audit_path()


def _coerce_bool(val: Any) -> Optional[bool]:
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        s = val.strip().lower()
        if s in {"1", "true", "t", "yes", "y", "on"}:
            return True
        if s in {"0", "false", "f", "no", "n", "off"}:
            return False
    if isinstance(val, (int, float)):
        return bool(val)
    return None


def _coerce_int(val: Any) -> Optional[int]:
    if isinstance(val, bool):
        return int(val)
    try:
        if isinstance(val, (int, float)):
            return int(val)
        return int(float(str(val).strip()))
    except Exception:
        return None


def _coerce_float(val: Any) -> Optional[float]:
    if isinstance(val, bool):
        return float(val)
    try:
        if isinstance(val, (int, float)):
            return float(val)
        return float(str(val).strip())
    except Exception:
        return None


def _normalize_config(data: Mapping[str, Any]) -> ConfigDict:
    normalized: Dict[str, Any] = {}

    if "shadow_enable" in data:
        bool_val = _coerce_bool(data.get("shadow_enable"))
        if bool_val is not None:
            normalized["shadow_enable"] = bool_val

    if "shadow_policy_path" in data:
        raw = data.get("shadow_policy_path")
        if raw is None:
            normalized["shadow_policy_path"] = ""
        else:
            s = str(raw).strip()
            normalized["shadow_policy_path"] = s

    if "shadow_timeout_ms" in data:
        int_val = _coerce_int(data.get("shadow_timeout_ms"))
        if int_val is not None and int_val >= 0:
            normalized["shadow_timeout_ms"] = int_val

    if "shadow_sample_rate" in data:
        float_val = _coerce_float(data.get("shadow_sample_rate"))
        if float_val is not None:
            clamped = max(0.0, min(1.0, float_val))
            normalized["shadow_sample_rate"] = clamped

    if "webhook_enable" in data:
        bool_val = _coerce_bool(data.get("webhook_enable"))
        if bool_val is not None:
            normalized["webhook_enable"] = bool_val

    if "webhook_url" in data:
        raw = data.get("webhook_url")
        if raw is None:
            normalized["webhook_url"] = ""
        else:
            normalized["webhook_url"] = str(raw).strip()

    if "webhook_secret" in data:
        raw = data.get("webhook_secret")
        if raw is None:
            normalized["webhook_secret"] = ""
        else:
            normalized["webhook_secret"] = str(raw).strip()

    if "webhook_timeout_ms" in data:
        int_val = _coerce_int(data.get("webhook_timeout_ms"))
        if int_val is not None and int_val >= 0:
            normalized["webhook_timeout_ms"] = int_val

    if "webhook_max_retries" in data:
        int_val = _coerce_int(data.get("webhook_max_retries"))
        if int_val is not None and int_val >= 0:
            normalized["webhook_max_retries"] = int_val

    if "webhook_backoff_ms" in data:
        int_val = _coerce_int(data.get("webhook_backoff_ms"))
        if int_val is not None and int_val >= 0:
            normalized["webhook_backoff_ms"] = int_val

    if "webhook_cb_error_threshold" in data:
        int_val = _coerce_int(data.get("webhook_cb_error_threshold"))
        if int_val is not None and int_val > 0:
            normalized["webhook_cb_error_threshold"] = int_val

    if "webhook_cb_window" in data:
        int_val = _coerce_int(data.get("webhook_cb_window"))
        if int_val is not None and int_val > 0:
            normalized["webhook_cb_window"] = int_val

    if "webhook_cb_cooldown_sec" in data:
        int_val = _coerce_int(data.get("webhook_cb_cooldown_sec"))
        if int_val is not None and int_val >= 0:
            normalized["webhook_cb_cooldown_sec"] = int_val

    if "webhook_backoff_cap_ms" in data:
        int_val = _coerce_int(data.get("webhook_backoff_cap_ms"))
        if int_val is not None and int_val >= 0:
            normalized["webhook_backoff_cap_ms"] = int_val

    if "webhook_allow_insecure_tls" in data:
        bool_val = _coerce_bool(data.get("webhook_allow_insecure_tls"))
        if bool_val is not None:
            normalized["webhook_allow_insecure_tls"] = bool_val

    if "webhook_allowlist_host" in data:
        raw = data.get("webhook_allowlist_host")
        if raw is None:
            normalized["webhook_allowlist_host"] = ""
        else:
            normalized["webhook_allowlist_host"] = str(raw).strip()

    return cast(ConfigDict, normalized)


def _load_config_locked() -> ConfigDict:
    _ensure_dirs()
    try:
        text = _ADMIN_CONFIG_PATH.read_text(encoding="utf-8")
    except FileNotFoundError:
        return cast(ConfigDict, {})
    except Exception:
        return cast(ConfigDict, {})

    try:
        raw = yaml.safe_load(text) or {}
    except Exception:
        return cast(ConfigDict, {})
    if not isinstance(raw, Mapping):
        return cast(ConfigDict, {})
    return _normalize_config(raw)


def _write_config_locked(state: Mapping[str, Any]) -> None:
    _ensure_dirs()
    payload: Dict[str, Any] = {}
    for key in _CONFIG_DEFAULTS.keys():
        if key in state:
            payload[key] = state[key]
    _ADMIN_CONFIG_PATH.write_text(
        yaml.safe_dump(payload, sort_keys=False), encoding="utf-8"
    )


def _ensure_config_loaded_locked() -> None:
    global _CONFIG_LOADED, _CONFIG_STATE
    if _CONFIG_LOADED:
        return
    _CONFIG_STATE = dict(_load_config_locked())
    _CONFIG_LOADED = True


def _env_overrides() -> ConfigDict:
    overrides: Dict[str, Any] = {}
    for key, env in _CONFIG_ENV_MAP.items():
        raw = os.getenv(env)
        if raw is None:
            continue
        if isinstance(raw, str) and raw.strip() == "":
            continue
        if key == "shadow_enable":
            bool_val = _coerce_bool(raw)
            if bool_val is not None:
                overrides[key] = bool_val
        elif key == "shadow_policy_path":
            overrides[key] = str(raw).strip()
        elif key == "shadow_timeout_ms":
            int_val = _coerce_int(raw)
            if int_val is not None and int_val >= 0:
                overrides[key] = int_val
        elif key == "shadow_sample_rate":
            float_val = _coerce_float(raw)
            if float_val is not None:
                overrides[key] = max(0.0, min(1.0, float_val))
        elif key == "webhook_enable":
            bool_val = _coerce_bool(raw)
            if bool_val is not None:
                overrides[key] = bool_val
        elif key == "webhook_url":
            overrides[key] = str(raw).strip()
        elif key == "webhook_secret":
            overrides[key] = str(raw).strip()
        elif key == "webhook_timeout_ms":
            int_val = _coerce_int(raw)
            if int_val is not None and int_val >= 0:
                overrides[key] = int_val
        elif key == "webhook_max_retries":
            int_val = _coerce_int(raw)
            if int_val is not None and int_val >= 0:
                overrides[key] = int_val
        elif key == "webhook_backoff_ms":
            int_val = _coerce_int(raw)
            if int_val is not None and int_val >= 0:
                overrides[key] = int_val
        elif key == "webhook_cb_error_threshold":
            int_val = _coerce_int(raw)
            if int_val is not None and int_val > 0:
                overrides[key] = int_val
        elif key == "webhook_cb_window":
            int_val = _coerce_int(raw)
            if int_val is not None and int_val > 0:
                overrides[key] = int_val
        elif key == "webhook_cb_cooldown_sec":
            int_val = _coerce_int(raw)
            if int_val is not None and int_val >= 0:
                overrides[key] = int_val
        elif key == "webhook_backoff_cap_ms":
            int_val = _coerce_int(raw)
            if int_val is not None and int_val >= 0:
                overrides[key] = int_val
        elif key == "webhook_allow_insecure_tls":
            bool_val = _coerce_bool(raw)
            if bool_val is not None:
                overrides[key] = bool_val
        elif key == "webhook_allowlist_host":
            overrides[key] = str(raw).strip()
    return cast(ConfigDict, overrides)


def _current_config_locked() -> ConfigDict:
    merged: Dict[str, Any] = dict(_CONFIG_DEFAULTS)
    merged.update(_CONFIG_STATE)
    merged.update(_env_overrides())
    return cast(ConfigDict, merged)


def get_config() -> ConfigDict:
    with _LOCK:
        _ensure_config_loaded_locked()
        return cast(ConfigDict, dict(_current_config_locked()))


def get_webhook_cb_tuning() -> Dict[str, int]:
    cfg = get_config()
    return {
        "webhook_cb_error_threshold": int(cfg.get("webhook_cb_error_threshold", 8) or 8),
        "webhook_cb_window": int(cfg.get("webhook_cb_window", 30) or 30),
        "webhook_cb_cooldown_sec": int(cfg.get("webhook_cb_cooldown_sec", 60) or 60),
        "webhook_backoff_cap_ms": int(cfg.get("webhook_backoff_cap_ms", 10_000) or 10_000),
    }


def _append_audit_entry(
    before_state: Mapping[str, Any], after_state: Mapping[str, Any], actor: str
) -> None:
    entry = {
        "ts": int(time.time() * 1000),
        "actor": actor,
        "before": dict(before_state),
        "after": dict(after_state),
    }
    path = _config_audit_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, separators=(",", ":")) + "\n")
    except Exception:
        # Never allow audit persistence failures to block config updates.
        pass


def set_config(
    patch: Mapping[str, Any], *, actor: str = "admin-api", replace: bool = False
) -> ConfigDict:
    with _LOCK:
        _ensure_config_loaded_locked()
        before_effective = dict(_current_config_locked())
        normalized = _normalize_config(patch)

        if "shadow_policy_path" in patch and "shadow_policy_path" not in normalized:
            normalized["shadow_policy_path"] = ""

        updated = False
        if replace:
            _CONFIG_STATE.clear()
            _CONFIG_STATE.update(normalized)
            _write_config_locked(_CONFIG_STATE)
            updated = True
        elif normalized:
            _CONFIG_STATE.update(normalized)
            _write_config_locked(_CONFIG_STATE)
            updated = True

        after_effective = dict(_current_config_locked())
        if updated and after_effective != before_effective:
            _append_audit_entry(before_effective, after_effective, actor)

        return cast(ConfigDict, after_effective)


def reset_config() -> None:
    global _CONFIG_LOADED, _CONFIG_STATE
    with _LOCK:
        _CONFIG_STATE = {}
        _CONFIG_LOADED = False
