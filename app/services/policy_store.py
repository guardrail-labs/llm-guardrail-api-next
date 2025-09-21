from __future__ import annotations

import os
from pathlib import Path
from types import ModuleType
from typing import Dict, Iterable, List, Optional

from app.services import config_store
from app.services.bindings.utils import (
    compute_version_for_path,
    propagate_bindings,
    read_policy_version,
)

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Environment overrides for legacy strict secrets pack resolution.
_PACK_ENV_OVERRIDES: Dict[str, str] = {
    "secrets_strict": "STRICT_SECRETS_POLICY_PATH",
}

# Fallback locations for well-known packs when the bindings store cannot
# resolve them dynamically. These paths mirror the legacy apply_* endpoints.
_PACK_FALLBACKS: Dict[str, str] = {
    "secrets_strict": "rules/policies/secrets/strict.yaml",
}


def _normalize_id(value: str) -> str:
    return (value or "").strip() or "default"


def _normalize_path(path: str) -> str:
    try:
        return str(Path(path).expanduser().resolve(strict=False))
    except Exception:
        return str(path)


def _resolve_pack_path(pack: str) -> str:
    pack_id = (pack or "").strip()
    if not pack_id:
        raise ValueError("pack is required")

    env = _PACK_ENV_OVERRIDES.get(pack_id)
    if env:
        override = os.getenv(env)
        if override:
            return str(Path(override).expanduser())

    _packs_mod: Optional[ModuleType]
    try:  # pragma: no cover - optional dependency
        from app.services import policy_packs as _packs_mod
    except Exception:  # pragma: no cover - policy packs unavailable
        _packs_mod = None

    if _packs_mod is not None:
        try:
            resolved = _packs_mod.resolve_pack_path(pack_id)
            if resolved is not None:
                return str(resolved)
        except Exception:
            pass

    fallback = _PACK_FALLBACKS.get(pack_id)
    if fallback:
        fallback_path = Path(fallback)
        if not fallback_path.is_absolute():
            roots = [
                Path.cwd() / fallback_path,
                _PROJECT_ROOT / fallback_path,
            ]
            for candidate in roots:
                try:
                    if candidate.exists():
                        return str(candidate.resolve(strict=False))
                except Exception:
                    continue
            try:
                project_candidate = (_PROJECT_ROOT / fallback_path).resolve(strict=False)
                return str(project_candidate)
            except Exception:
                return str(_PROJECT_ROOT / fallback_path)
        try:
            return str(fallback_path.resolve(strict=False))
        except Exception:
            return str(fallback_path)

    # Treat unknown packs as direct paths for forward compatibility.
    return pack_id


def _serialize_bindings(bindings: Iterable[config_store.Binding]) -> List[Dict[str, str]]:
    payload: List[Dict[str, str]] = []
    for item in bindings:
        rules_path = item["rules_path"]
        version = compute_version_for_path(rules_path)
        policy_version = read_policy_version(rules_path) or version
        payload.append(
            {
                "tenant": item["tenant"],
                "bot": item["bot"],
                "rules_path": rules_path,
                "version": version,
                "policy_version": policy_version,
            }
        )
    return payload


def _apply_runtime_bindings(payload: List[Dict[str, str]]) -> None:
    try:
        propagate_bindings(payload)
    except Exception:
        pass

    try:
        from app import main as main_mod
    except Exception:
        return

    bindings_map = getattr(main_mod, "_BINDINGS", None)
    if not isinstance(bindings_map, dict):
        return

    try:
        bindings_map.clear()
        for entry in payload:
            bindings_map[(entry["tenant"], entry["bot"])] = {
                "rules_path": entry["rules_path"],
                "version": entry["version"],
                "policy_version": entry["policy_version"],
            }
    except Exception:
        pass


def _refresh_runtime() -> None:
    doc = config_store.load_bindings()
    payload = _serialize_bindings(doc.bindings)
    _apply_runtime_bindings(payload)


def is_bound(tenant: str, bot: str, pack: str) -> bool:
    """Return True when the binding for {tenant, bot} targets ``pack``."""

    tenant_norm = _normalize_id(tenant)
    bot_norm = _normalize_id(bot)
    target = _normalize_path(_resolve_pack_path(pack))

    doc = config_store.load_bindings()
    for binding in doc.bindings:
        if (
            _normalize_id(binding["tenant"]) == tenant_norm
            and _normalize_id(binding["bot"]) == bot_norm
            and _normalize_path(binding["rules_path"]) == target
        ):
            return True
    return False


def bind_pack(tenant: str, bot: str, pack: str) -> None:
    """Bind ``pack`` to the specified {tenant, bot} and refresh runtime caches."""

    path = _resolve_pack_path(pack)
    config_store.upsert_binding(tenant, bot, path)
    _refresh_runtime()


def unbind_pack(tenant: str, bot: str, pack: str) -> None:
    """Remove ``pack`` binding for {tenant, bot} when present."""

    tenant_norm = _normalize_id(tenant)
    bot_norm = _normalize_id(bot)
    target = _normalize_path(_resolve_pack_path(pack))

    doc = config_store.load_bindings()
    updated: List[config_store.Binding] = []
    removed = False
    for binding in doc.bindings:
        if (
            _normalize_id(binding["tenant"]) == tenant_norm
            and _normalize_id(binding["bot"]) == bot_norm
            and _normalize_path(binding["rules_path"]) == target
        ):
            removed = True
            continue
        updated.append(binding)

    if not removed:
        return

    config_store.save_bindings(updated)
    _refresh_runtime()
