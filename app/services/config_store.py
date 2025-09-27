from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from typing import Any, Dict, Iterable, List, Mapping, Optional, TypedDict, cast

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
    ingress_header_limits_enabled: bool
    ingress_max_header_count: int
    ingress_max_header_value_bytes: int
    ingress_duplicate_header_guard_mode: str
    ingress_duplicate_header_unique: List[str]
    ingress_duplicate_header_metric_allowlist: List[str]
    ingress_unicode_sanitizer_enabled: bool
    ingress_unicode_header_sample_bytes: int
    ingress_unicode_query_sample_bytes: int
    ingress_unicode_path_sample_chars: int
    ingress_unicode_enforce_mode: str
    ingress_unicode_enforce_flags: List[str]
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
    webhook_signing_mode: str
    webhook_signing_dual: bool
    policy_packs: List[str]
    admin_rbac_enabled: bool
    admin_api_key: str


_UNICODE_ENFORCE_MODES = {"off", "log", "block"}
_UNICODE_FLAG_KEYS = {"bidi", "zwc", "emoji", "confusables", "mixed"}
_UNICODE_DEFAULT_FLAGS: List[str] = ["bidi", "zwc"]

DUPLICATE_HEADER_GUARD_MODES = {"off", "log", "block"}
DUPLICATE_HEADER_UNIQUE_DEFAULT: List[str] = [
    "content-length",
    "transfer-encoding",
    "host",
    "authorization",
    "x-request-id",
    "traceparent",
    "x-guardrail-tenant",
    "x-guardrail-bot",
]

DUPLICATE_HEADER_METRIC_ALLOWLIST_DEFAULT: List[str] = [
    "content-length",
    "transfer-encoding",
    "host",
    "authorization",
    "x-request-id",
    "traceparent",
    "x-guardrail-tenant",
    "x-guardrail-bot",
    "content-type",
    "accept",
    "cookie",
    "set-cookie",
]


_CONFIG_DEFAULTS: ConfigDict = {
    "shadow_enable": False,
    "shadow_policy_path": "",
    "shadow_timeout_ms": 100,
    "shadow_sample_rate": 1.0,
    "ingress_header_limits_enabled": False,
    "ingress_max_header_count": 0,
    "ingress_max_header_value_bytes": 0,
    "ingress_duplicate_header_guard_mode": "off",
    "ingress_duplicate_header_unique": list(DUPLICATE_HEADER_UNIQUE_DEFAULT),
    # Headers allowed to appear as individual metric label values. Keep this list
    # short and stable to avoid cardinality spikes.
    "ingress_duplicate_header_metric_allowlist": list(DUPLICATE_HEADER_METRIC_ALLOWLIST_DEFAULT),
    "ingress_unicode_sanitizer_enabled": False,
    "ingress_unicode_header_sample_bytes": 4096,
    "ingress_unicode_query_sample_bytes": 4096,
    "ingress_unicode_path_sample_chars": 1024,
    "ingress_unicode_enforce_mode": "off",
    "ingress_unicode_enforce_flags": list(_UNICODE_DEFAULT_FLAGS),
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
    # Webhook signing mode:
    #  - "body" (v0): HMAC over raw body only (current default)
    #  - "ts_body" (v1): HMAC over f"{timestamp}\n{raw_body}" and emit timestamp header
    "webhook_signing_mode": "body",
    # When mode == "ts_body": also emit legacy v0 header in parallel for migration
    "webhook_signing_dual": True,
    "policy_packs": ["base"],
    "admin_rbac_enabled": False,
    "admin_api_key": "",
}

_CONFIG_ENV_MAP: Dict[str, str] = {
    "shadow_enable": "SHADOW_ENABLE",
    "shadow_policy_path": "SHADOW_POLICY_PATH",
    "shadow_timeout_ms": "SHADOW_TIMEOUT_MS",
    "shadow_sample_rate": "SHADOW_SAMPLE_RATE",
    "ingress_header_limits_enabled": "INGRESS_HEADER_LIMITS_ENABLED",
    "ingress_max_header_count": "INGRESS_MAX_HEADER_COUNT",
    "ingress_max_header_value_bytes": "INGRESS_MAX_HEADER_VALUE_BYTES",
    "ingress_duplicate_header_guard_mode": "INGRESS_DUPLICATE_HEADER_GUARD_MODE",
    "ingress_duplicate_header_unique": "INGRESS_DUPLICATE_HEADER_UNIQUE",
    "ingress_duplicate_header_metric_allowlist": "INGRESS_DUPLICATE_HEADER_METRIC_ALLOWLIST",
    "ingress_unicode_sanitizer_enabled": "INGRESS_UNICODE_SANITIZER_ENABLED",
    "ingress_unicode_header_sample_bytes": "INGRESS_UNICODE_HEADER_SAMPLE_BYTES",
    "ingress_unicode_query_sample_bytes": "INGRESS_UNICODE_QUERY_SAMPLE_BYTES",
    "ingress_unicode_path_sample_chars": "INGRESS_UNICODE_PATH_SAMPLE_CHARS",
    "ingress_unicode_enforce_mode": "INGRESS_UNICODE_ENFORCE_MODE",
    "ingress_unicode_enforce_flags": "INGRESS_UNICODE_ENFORCE_FLAGS",
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
    "webhook_signing_mode": "WEBHOOK_SIGNING_MODE",
    "webhook_signing_dual": "WEBHOOK_SIGNING_DUAL",
    "policy_packs": "POLICY_PACKS",
    "admin_rbac_enabled": "ADMIN_RBAC_ENABLED",
    "admin_api_key": "ADMIN_API_KEY",
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


def _parse_policy_packs(val: Any) -> Optional[List[str]]:
    if val is None:
        return None
    if isinstance(val, str):
        items = [s.strip() for s in val.split(",") if s and s.strip()]
        return items or None
    if isinstance(val, (list, tuple)):
        items = [str(x).strip() for x in val if str(x).strip()]
        return items or None
    return None


def _parse_unicode_enforce_flags(val: Any) -> Optional[List[str]]:
    if val is None:
        return None
    tokens: List[str]
    if isinstance(val, str):
        tokens = [s.strip().lower() for s in val.split(",") if s and s.strip()]
    elif isinstance(val, (list, tuple, set)):
        tokens = [str(item).strip().lower() for item in val if str(item).strip()]
    else:
        return None
    seen: set[str] = set()
    filtered: List[str] = []
    for token in tokens:
        if token in _UNICODE_FLAG_KEYS and token not in seen:
            seen.add(token)
            filtered.append(token)
    return filtered or None


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

    if "ingress_header_limits_enabled" in data:
        bool_val = _coerce_bool(data.get("ingress_header_limits_enabled"))
        if bool_val is not None:
            normalized["ingress_header_limits_enabled"] = bool_val

    if "ingress_max_header_count" in data:
        int_val = _coerce_int(data.get("ingress_max_header_count"))
        if int_val is not None and int_val >= 0:
            normalized["ingress_max_header_count"] = int_val

    if "ingress_max_header_value_bytes" in data:
        int_val = _coerce_int(data.get("ingress_max_header_value_bytes"))
        if int_val is not None and int_val >= 0:
            normalized["ingress_max_header_value_bytes"] = int_val

    if "ingress_duplicate_header_guard_mode" in data:
        raw = data.get("ingress_duplicate_header_guard_mode")
        if raw is None:
            normalized["ingress_duplicate_header_guard_mode"] = "off"
        else:
            mode = str(raw).strip().lower()
            if mode in DUPLICATE_HEADER_GUARD_MODES:
                normalized["ingress_duplicate_header_guard_mode"] = mode

    if "ingress_duplicate_header_unique" in data:
        raw_unique = data.get("ingress_duplicate_header_unique")
        if raw_unique is None:
            normalized["ingress_duplicate_header_unique"] = list(DUPLICATE_HEADER_UNIQUE_DEFAULT)
        else:
            if isinstance(raw_unique, str):
                iterable: Iterable[Any] = raw_unique.split(",")
            elif isinstance(raw_unique, Iterable):
                iterable = raw_unique
            else:
                iterable = [raw_unique]
            items: list[str] = []
            for item in iterable:
                token = str(item).strip().lower()
                if token:
                    items.append(token)
            if items:
                deduped = list(dict.fromkeys(items))
                normalized["ingress_duplicate_header_unique"] = deduped

    if "ingress_duplicate_header_metric_allowlist" in data:
        raw_allow = data.get("ingress_duplicate_header_metric_allowlist")
        if raw_allow is None:
            normalized["ingress_duplicate_header_metric_allowlist"] = list(
                DUPLICATE_HEADER_METRIC_ALLOWLIST_DEFAULT
            )
        else:
            if isinstance(raw_allow, str):
                iterable_allow: Iterable[Any] = raw_allow.split(",")
            elif isinstance(raw_allow, Iterable):
                iterable_allow = raw_allow
            else:
                iterable_allow = [raw_allow]
            allow_items: list[str] = []
            for item in iterable_allow:
                token = str(item).strip().lower()
                if token:
                    allow_items.append(token)
            if allow_items:
                deduped_allow = list(dict.fromkeys(allow_items))
                normalized["ingress_duplicate_header_metric_allowlist"] = deduped_allow

    if "ingress_unicode_sanitizer_enabled" in data:
        bool_val = _coerce_bool(data.get("ingress_unicode_sanitizer_enabled"))
        if bool_val is not None:
            normalized["ingress_unicode_sanitizer_enabled"] = bool_val

    if "ingress_unicode_header_sample_bytes" in data:
        int_val = _coerce_int(data.get("ingress_unicode_header_sample_bytes"))
        if int_val is not None and int_val >= 0:
            normalized["ingress_unicode_header_sample_bytes"] = int_val

    if "ingress_unicode_query_sample_bytes" in data:
        int_val = _coerce_int(data.get("ingress_unicode_query_sample_bytes"))
        if int_val is not None and int_val >= 0:
            normalized["ingress_unicode_query_sample_bytes"] = int_val

    if "ingress_unicode_path_sample_chars" in data:
        int_val = _coerce_int(data.get("ingress_unicode_path_sample_chars"))
        if int_val is not None and int_val >= 0:
            normalized["ingress_unicode_path_sample_chars"] = int_val

    if "ingress_unicode_enforce_mode" in data:
        raw = data.get("ingress_unicode_enforce_mode")
        if raw is None:
            normalized["ingress_unicode_enforce_mode"] = "off"
        else:
            mode = str(raw).strip().lower()
            if mode in _UNICODE_ENFORCE_MODES:
                normalized["ingress_unicode_enforce_mode"] = mode

    if "ingress_unicode_enforce_flags" in data:
        flags = _parse_unicode_enforce_flags(data.get("ingress_unicode_enforce_flags"))
        if flags is not None:
            normalized["ingress_unicode_enforce_flags"] = flags
        elif data.get("ingress_unicode_enforce_flags") is None:
            normalized["ingress_unicode_enforce_flags"] = list(_UNICODE_DEFAULT_FLAGS)

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

    if "webhook_signing_mode" in data:
        raw = data.get("webhook_signing_mode")
        if raw is None:
            normalized["webhook_signing_mode"] = "body"
        else:
            mode = str(raw).strip().lower()
            if mode in {"body", "ts_body"}:
                normalized["webhook_signing_mode"] = mode

    if "webhook_signing_dual" in data:
        bool_val = _coerce_bool(data.get("webhook_signing_dual"))
        if bool_val is not None:
            normalized["webhook_signing_dual"] = bool_val

    if "policy_packs" in data:
        packs = _parse_policy_packs(data.get("policy_packs"))
        if packs is not None:
            normalized["policy_packs"] = packs
        elif data.get("policy_packs") is None:
            normalized["policy_packs"] = ["base"]

    if "admin_rbac_enabled" in data:
        bool_val = _coerce_bool(data.get("admin_rbac_enabled"))
        if bool_val is not None:
            normalized["admin_rbac_enabled"] = bool_val

    if "admin_api_key" in data:
        raw = data.get("admin_api_key")
        if raw is None:
            normalized["admin_api_key"] = ""
        else:
            normalized["admin_api_key"] = str(raw).strip()

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
    _ADMIN_CONFIG_PATH.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")


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
        elif key == "ingress_header_limits_enabled":
            bool_val = _coerce_bool(raw)
            if bool_val is not None:
                overrides[key] = bool_val
        elif key == "ingress_max_header_count":
            int_val = _coerce_int(raw)
            if int_val is not None and int_val >= 0:
                overrides[key] = int_val
        elif key == "ingress_max_header_value_bytes":
            int_val = _coerce_int(raw)
            if int_val is not None and int_val >= 0:
                overrides[key] = int_val
        elif key == "ingress_unicode_enforce_mode":
            mode = str(raw).strip().lower()
            if mode in _UNICODE_ENFORCE_MODES:
                overrides[key] = mode
        elif key == "ingress_unicode_enforce_flags":
            flags = _parse_unicode_enforce_flags(raw)
            if flags is not None:
                overrides[key] = flags
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
        elif key == "webhook_signing_mode":
            mode = str(raw).strip().lower()
            if mode in {"body", "ts_body"}:
                overrides[key] = mode
        elif key == "webhook_signing_dual":
            bool_val = _coerce_bool(raw)
            if bool_val is not None:
                overrides[key] = bool_val
        elif key == "policy_packs":
            packs = _parse_policy_packs(raw)
            if packs is not None:
                overrides[key] = packs
        elif key == "admin_rbac_enabled":
            bool_val = _coerce_bool(raw)
            if bool_val is not None:
                overrides[key] = bool_val
        elif key == "admin_api_key":
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


def get_webhook_signing() -> Dict[str, Any]:
    cfg = get_config()
    raw_mode = cfg.get("webhook_signing_mode", "body")
    mode = str(raw_mode or "body").strip().lower()
    if mode not in {"body", "ts_body"}:
        mode = "body"

    raw_dual = cfg.get("webhook_signing_dual", True)
    bool_dual = _coerce_bool(raw_dual)
    dual = True if bool_dual is None else bool_dual

    return {"mode": mode, "dual": dual}


def get_policy_packs() -> List[str]:
    cfg = get_config()
    val = cfg.get("policy_packs", ["base"])
    if isinstance(val, str):
        items = [s.strip() for s in val.split(",") if s.strip()]
        return items or ["base"]
    if isinstance(val, (list, tuple)):
        items = [str(x).strip() for x in val if str(x).strip()]
        return items or ["base"]
    return ["base"]


def is_admin_rbac_enabled() -> bool:
    cfg = get_config()
    return bool(cfg.get("admin_rbac_enabled", False))


def get_admin_api_key() -> str:
    cfg = get_config()
    return str(cfg.get("admin_api_key", "") or "")


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
