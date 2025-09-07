# File: app/services/policy_loader.py
from __future__ import annotations

import contextvars
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Pattern, Tuple

import yaml

from app.config import Settings


@dataclass
class PolicyBlob:
    rules: dict
    version: str
    path: str
    mtime: float
    # List of (rule_id, compiled_pattern)
    deny_compiled: List[Tuple[str, Pattern[str]]]


# Cache keyed by absolute rules path
_cache: Dict[str, PolicyBlob] = {}

# Binding context (optional; defaults keep legacy behavior stable)
_CTX_TENANT: contextvars.ContextVar[str] = contextvars.ContextVar(
    "policy_tenant", default="default"
)
_CTX_BOT: contextvars.ContextVar[str] = contextvars.ContextVar(
    "policy_bot", default="default"
)


def set_binding_context(tenant: str, bot: str) -> None:
    """Set the current {tenant, bot} binding context for resolution."""
    _CTX_TENANT.set((tenant or "default").strip() or "default")
    _CTX_BOT.set((bot or "default").strip() or "default")


def _default_path() -> str:
    return str(
        Path(__file__).resolve().parent.parent / "policy" / "rules.yaml"
    )


def _binding_path_or_none(tenant: str, bot: str) -> str | None:
    """
    Best-effort consult of the optional binding store:
      resolve_rules_path(tenant, bot) -> dict with 'rules_path' (preferred)
      or a (rules_path, source) tuple in older shapes.
    """
    try:
        from app.services import config_store as _cs

        resolver = getattr(_cs, "resolve_rules_path", None)
        if not callable(resolver):
            return None

        resolved = resolver(tenant, bot)
        # Dict shape preferred
        if isinstance(resolved, dict):
            rp = resolved.get("rules_path")
            return str(rp) if rp else None

        # Tuple(shape) fallback
        try:
            rp, _src = resolved  # type: ignore[unused-ignore]  # nosec - best effort
            return str(rp)
        except Exception:
            return None
    except Exception:
        return None


def _resolve_path() -> str:
    """
    Resolution priority (to satisfy tests and keep ops intuitive):
      1) Explicit ENV override: POLICY_RULES_PATH (if set and non-empty)
      2) Binding store (if present) for current {tenant, bot}
      3) Bundled default rules.yaml
    """
    s = Settings()

    # 1) ENV override
    env_path = (s.POLICY_RULES_PATH or "").strip()
    if env_path:
        return env_path

    # 2) Binding store (optional)
    tenant = _CTX_TENANT.get()
    bot = _CTX_BOT.get()
    bound = _binding_path_or_none(tenant, bot)
    if bound:
        return bound

    # 3) Bundled default
    return _default_path()


def _flag_bits(flags: List[str] | None) -> int:
    """Translate YAML flags like ['i','m','s'] into re flags."""
    if not flags:
        return 0
    mapping = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}
    bits = 0
    for f in flags:
        if f in mapping:
            bits |= mapping[f]
    return bits


def _compile_deny(rules: dict) -> List[Tuple[str, Pattern[str]]]:
    out: List[Tuple[str, Pattern[str]]] = []
    deny = rules.get("deny", [])
    if not isinstance(deny, list):
        return out
    for item in deny:
        if not isinstance(item, dict):
            continue
        rid = str(item.get("id", "")).strip() or "unnamed"
        pat = str(item.get("pattern", ""))
        flags = _flag_bits(item.get("flags"))
        try:
            cp = re.compile(pat, flags)
            out.append((rid, cp))
        except re.error:
            # Skip invalid regex; policy authors can fix in file
            continue
    return out


def _load_from_disk(path: str) -> PolicyBlob:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    rules = yaml.safe_load(text) or {}
    mtime = p.stat().st_mtime
    version = str(rules.get("version", int(mtime)))
    deny_compiled = _compile_deny(rules)
    return PolicyBlob(
        rules=rules,
        version=version,
        path=str(p),
        mtime=mtime,
        deny_compiled=deny_compiled,
    )


def get_policy() -> PolicyBlob:
    """Return the current policy; refresh if POLICY_AUTORELOAD and mtime changed."""
    path = _resolve_path()
    s = Settings()

    blob = _cache.get(path)
    if blob is None:
        blob = _load_from_disk(path)
        _cache[path] = blob
        return blob

    if s.POLICY_AUTORELOAD:
        try:
            mtime = Path(path).stat().st_mtime
        except FileNotFoundError:
            return blob
        if mtime != blob.mtime:
            blob = _load_from_disk(path)
            _cache[path] = blob

    return blob


def reload_now() -> PolicyBlob:
    """Force a reload regardless of POLICY_AUTORELOAD."""
    path = _resolve_path()
    blob = _load_from_disk(path)
    _cache[path] = blob
    return blob


# ---- Optional binding inspection (admin ergonomics) --------------------------

def describe_binding(tenant: str, bot: str) -> Dict[str, object]:
    """
    Best-effort view of which rules path would be used for a {tenant, bot}.
    Always reflects ENV override if present.
    """
    info: Dict[str, object] = {"tenant": tenant, "bot": bot}

    # ENV override takes precedence and should be visible to operators/tests.
    env_path = (Settings().POLICY_RULES_PATH or "").strip()
    if env_path:
        info["rules_path"] = env_path
        info["source"] = "env"
    else:
        # Otherwise, show binding resolution (if any), or default.
        try:
            bound = _binding_path_or_none(tenant, bot)
        except Exception:
            bound = None
        if bound:
            info["rules_path"] = bound
            info["source"] = "binding"
        else:
            info["rules_path"] = _default_path()
            info["source"] = "default"

    # Include current effective version if available
    try:
        blob = get_policy()
        info["version"] = blob.version
    except Exception:
        info.setdefault("version", "unknown")

    return info
