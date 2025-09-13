from __future__ import annotations

import os
from typing import Any, Dict, Literal, Optional

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from app.security.admin_auth import require_admin
from app.services.rulepacks_engine import egress_mode, ingress_mode, rulepacks_enabled

try:
    from app.services.policy import (
        current_rules_version as _current_rules_version,
        map_classifier_outcome_to_action as _map_classifier_outcome_to_action,
        map_verifier_outcome_to_action as _map_verifier_outcome_to_action,
    )
except Exception:  # pragma: no cover
    def _current_rules_version() -> str:
        return os.getenv("POLICY_VERSION", "test-policy")

    def _map_classifier_outcome_to_action(
        o: Literal["allow", "block", "ambiguous", "unknown"],
    ) -> str:
        return {"allow": "allow", "block": "block_input_only"}.get(o, "clarify")

    def _map_verifier_outcome_to_action(
        o: Literal["allow", "block", "timeout", "error", "uncertain"],
    ) -> str:
        return {"allow": "allow", "block": "block_input_only"}.get(o, "clarify")

current_rules_version = _current_rules_version
map_classifier_outcome_to_action = _map_classifier_outcome_to_action
map_verifier_outcome_to_action = _map_verifier_outcome_to_action

router = APIRouter(prefix="/admin/policies", tags=["admin"], dependencies=[Depends(require_admin)])


def _env_flag(name: str, default: str = "0", overrides: Optional[Dict[str, str]] = None) -> str:
    if overrides and name in overrides:
        return overrides[name]
    return os.getenv(name, default)


def _collect_active_policy(overrides: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    env_toggles: Dict[str, Any] = {
        "CORS_ENABLED": _env_flag("CORS_ENABLED", "0", overrides),
        "EGRESS_FILTER_ENABLED": _env_flag("EGRESS_FILTER_ENABLED", "1", overrides),
        "EGRESS_SUMMARIZE_ENABLED": _env_flag("EGRESS_SUMMARIZE_ENABLED", "0", overrides),
        "EGRESS_POLICY_CHECK_ENABLED": _env_flag("EGRESS_POLICY_CHECK_ENABLED", "0", overrides),
        "CLARIFY_HTTP_STATUS": _env_flag("CLARIFY_HTTP_STATUS", "422", overrides),
    }
    env_toggles.update({
        "RULEPACKS_ENFORCE": "1" if rulepacks_enabled() else "0",
        "RULEPACKS_ACTIVE": os.getenv("RULEPACKS_ACTIVE", ""),
        "RULEPACKS_INGRESS_MODE": ingress_mode(),
        "RULEPACKS_EGRESS_MODE": egress_mode(),
    })
    decision_map = {
        "classifier.allow": map_classifier_outcome_to_action("allow"),
        "classifier.block": map_classifier_outcome_to_action("block"),
        "classifier.ambiguous": map_classifier_outcome_to_action("ambiguous"),
        "verifier.allow": map_verifier_outcome_to_action("allow"),
        "verifier.block": map_verifier_outcome_to_action("block"),
        "verifier.timeout": map_verifier_outcome_to_action("timeout"),
        "verifier.uncertain": map_verifier_outcome_to_action("uncertain"),
    }
    return {
        "policy_version": (
            current_rules_version()
            if callable(current_rules_version)
            else str(current_rules_version)
        ),
        "env_toggles": env_toggles,
        "decision_map": decision_map,
    }


@router.get("/active")
def get_active_policy() -> JSONResponse:
    return JSONResponse(_collect_active_policy())


@router.post("/preview")
def preview_policy(proposed: Dict[str, Any]) -> JSONResponse:
    """
    Dry-run preview of active policy with overrides; does NOT persist changes.
    Body example:
      { "env_overrides": { "EGRESS_SUMMARIZE_ENABLED": "1", "CLARIFY_HTTP_STATUS": "400" } }
    """
    overrides = proposed.get("env_overrides") if isinstance(proposed, dict) else None
    if overrides is not None and not isinstance(overrides, dict):
        return JSONResponse({"error": "env_overrides must be an object"}, status_code=400)

    current = _collect_active_policy()
    preview = _collect_active_policy(overrides=overrides)

    # Simple diff
    changed: Dict[str, Any] = {}
    if overrides:
        for k, v in overrides.items():
            before = current["env_toggles"].get(k)
            after = preview["env_toggles"].get(k)
            if before != after:
                changed[k] = {"before": before, "after": after}

    payload = {
        "preview": preview,
        "changed": changed,
        "note": "Preview only — no changes applied.",
    }
    return JSONResponse(payload)
