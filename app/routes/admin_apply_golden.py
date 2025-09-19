from __future__ import annotations

import os
from importlib import import_module
from pathlib import Path
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException

from app.security.admin_auth import require_admin
from app.services import config_store
from app.services.bindings.utils import (
    compute_version_for_path,
    propagate_bindings,
    read_policy_version,
)
from app.services.config_store import Binding

DEFAULT_GOLDEN_POLICY = "rules/policies/golden/default.yaml"

router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(require_admin)],
)


def _resolved_golden_path() -> str:
    raw = (os.getenv("GOLDEN_POLICY_PATH") or DEFAULT_GOLDEN_POLICY).strip()
    if not raw:
        raw = DEFAULT_GOLDEN_POLICY
    path = Path(raw).expanduser().resolve()
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Golden policy not found.")
    return str(path)


def _serialize_binding(binding: Binding) -> Dict[str, str]:
    rules_path = binding["rules_path"]
    version = compute_version_for_path(rules_path)
    policy_version = read_policy_version(rules_path) or version
    return {
        "tenant": binding["tenant"],
        "bot": binding["bot"],
        "rules_path": rules_path,
        "version": version,
        "policy_version": policy_version,
    }


def _update_inmemory_bindings(payload: List[Dict[str, str]]) -> None:
    try:
        main_mod = import_module("app.main")
    except Exception:
        return
    bindings_map = getattr(main_mod, "_BINDINGS", None)
    if not isinstance(bindings_map, dict):
        return
    try:
        bindings_map.clear()
        for item in payload:
            bindings_map[(item["tenant"], item["bot"])] = {
                "rules_path": item["rules_path"],
                "version": item["version"],
                "policy_version": item["policy_version"],
            }
    except Exception:
        pass


@router.post("/bindings/apply_golden")
def apply_golden_packs(payload: Dict[str, Any]) -> Dict[str, Any]:
    tenant = str(payload.get("tenant", "")).strip()
    bot = str(payload.get("bot", "")).strip()
    if not tenant or not bot:
        raise HTTPException(status_code=400, detail="tenant and bot are required.")

    rules_path = _resolved_golden_path()

    doc = config_store.load_bindings()
    for binding in doc.bindings:
        if binding["tenant"] == tenant and binding["bot"] == bot:
            if binding["rules_path"] == rules_path:
                version = compute_version_for_path(rules_path)
                policy_version = read_policy_version(rules_path) or version
                return {
                    "tenant": tenant,
                    "bot": bot,
                    "rules_path": rules_path,
                    "applied": False,
                    "version": version,
                    "policy_version": policy_version,
                }
            break

    updated_doc = config_store.upsert_binding(tenant, bot, rules_path)
    serialized = [_serialize_binding(b) for b in updated_doc.bindings]

    try:
        propagate_bindings(serialized)
    except Exception:
        pass
    _update_inmemory_bindings(serialized)

    version = compute_version_for_path(rules_path)
    policy_version = read_policy_version(rules_path) or version

    return {
        "tenant": tenant,
        "bot": bot,
        "rules_path": rules_path,
        "applied": True,
        "version": version,
        "policy_version": policy_version,
    }
