from __future__ import annotations

import os
from importlib import import_module
from pathlib import Path
from typing import Any, Dict, List, Tuple

from fastapi import APIRouter, Depends, HTTPException

from app.observability.admin_audit import record
from app.observability.metrics import admin_audit_total
from app.security import rbac
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


def _parse_tenant_bot(payload: Dict[str, Any]) -> Tuple[str, str]:
    tenant = str(payload.get("tenant", "")).strip()
    bot = str(payload.get("bot", "")).strip()
    if not tenant or not bot:
        raise HTTPException(status_code=400, detail="tenant and bot are required.")
    return tenant, bot


def _apply_golden(tenant: str, bot: str) -> Dict[str, Any]:
    rules_path = _resolved_golden_path()

    doc = config_store.load_bindings()
    existing_binding = None
    for binding in doc.bindings:
        if binding["tenant"] == tenant and binding["bot"] == bot:
            existing_binding = binding
            break

    if existing_binding and existing_binding["rules_path"] == rules_path:
        applied = False
        bindings_doc = doc
    else:
        bindings_doc = config_store.upsert_binding(tenant, bot, rules_path)
        applied = True

    serialized = [_serialize_binding(b) for b in bindings_doc.bindings]

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
        "applied": applied,
        "version": version,
        "policy_version": policy_version,
    }


@router.post("/bindings/apply_golden")
def apply_golden_packs(
    payload: Dict[str, Any],
    user: Dict[str, Any] = Depends(rbac.require_operator),
) -> Dict[str, Any]:
    tenant, bot = _parse_tenant_bot(payload)
    actor_email = (user or {}).get("email") if isinstance(user, dict) else None
    actor_role = (user or {}).get("role") if isinstance(user, dict) else None
    try:
        result = _apply_golden(tenant, bot)
    except HTTPException as exc:
        try:
            admin_audit_total.labels("apply_golden", "error").inc()
        except Exception:
            pass
        record(
            action="apply_golden",
            actor_email=actor_email,
            actor_role=actor_role,
            tenant=tenant,
            bot=bot,
            outcome="error",
            meta={"error": exc.detail},
        )
        raise
    except Exception as exc:  # pragma: no cover - unexpected failure
        try:
            admin_audit_total.labels("apply_golden", "error").inc()
        except Exception:
            pass
        record(
            action="apply_golden",
            actor_email=actor_email,
            actor_role=actor_role,
            tenant=tenant,
            bot=bot,
            outcome="error",
            meta={"error": str(exc)},
        )
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    try:
        admin_audit_total.labels("apply_golden", "ok").inc()
    except Exception:
        pass
    record(
        action="apply_golden",
        actor_email=actor_email,
        actor_role=actor_role,
        tenant=tenant,
        bot=bot,
        outcome="ok",
        meta={
            "rules_path": result.get("rules_path"),
            "applied": bool(result.get("applied")),
            "version": result.get("version"),
            "policy_version": result.get("policy_version"),
        },
    )
    return result


def apply_golden_action(payload: Dict[str, Any]) -> Dict[str, Any]:
    tenant, bot = _parse_tenant_bot(payload)
    return _apply_golden(tenant, bot)
