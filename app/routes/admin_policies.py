from __future__ import annotations

import os
from typing import Any, Callable, Dict, Literal

from fastapi import APIRouter
from fastapi.responses import JSONResponse

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
        o: Literal["allow", "block", "ambiguous", "unknown"]
    ) -> str:
        return {"allow": "allow", "block": "block_input_only"}.get(o, "clarify")

    def _map_verifier_outcome_to_action(
        o: Literal["allow", "block", "timeout", "error", "uncertain"]
    ) -> str:
        return {"allow": "allow", "block": "block_input_only"}.get(o, "clarify")

current_rules_version = _current_rules_version
map_classifier_outcome_to_action = _map_classifier_outcome_to_action
map_verifier_outcome_to_action = _map_verifier_outcome_to_action


router = APIRouter(prefix="/admin/policies", tags=["admin"])


def _env_flag(name: str, default: str = "0") -> str:
    return os.getenv(name, default)


@router.get("/active")
def get_active_policy() -> JSONResponse:
    env_toggles: Dict[str, Any] = {
        "CORS_ENABLED": _env_flag("CORS_ENABLED", "0"),
        "EGRESS_FILTER_ENABLED": _env_flag("EGRESS_FILTER_ENABLED", "1"),
        "EGRESS_SUMMARIZE_ENABLED": _env_flag("EGRESS_SUMMARIZE_ENABLED", "0"),
        "EGRESS_POLICY_CHECK_ENABLED": _env_flag("EGRESS_POLICY_CHECK_ENABLED", "0"),
        "CLARIFY_HTTP_STATUS": _env_flag("CLARIFY_HTTP_STATUS", "422"),
    }
    decision_map = {
        "classifier.allow": map_classifier_outcome_to_action("allow"),
        "classifier.block": map_classifier_outcome_to_action("block"),
        "classifier.ambiguous": map_classifier_outcome_to_action("ambiguous"),
        "verifier.allow": map_verifier_outcome_to_action("allow"),
        "verifier.block": map_verifier_outcome_to_action("block"),
        "verifier.timeout": map_verifier_outcome_to_action("timeout"),
        "verifier.uncertain": map_verifier_outcome_to_action("uncertain"),
    }
    payload = {
        "policy_version": (
            current_rules_version()
            if callable(current_rules_version)
            else str(current_rules_version)
        ),
        "env_toggles": env_toggles,
        "decision_map": decision_map,
    }
    return JSONResponse(payload)

