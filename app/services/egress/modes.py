from __future__ import annotations

import os
from typing import Any, Dict, Tuple

from app.services.egress.filter import DEFAULT_REDACTIONS, transform_with
from app.services.rulepacks_engine import egress_mode, egress_redactions

SUMMARIZE_ENABLED = os.getenv("EGRESS_SUMMARIZE_ENABLED", "0") == "1"
POLICY_CHECK_ENABLED = os.getenv("EGRESS_POLICY_CHECK_ENABLED", "0") == "1"


def summarize_text(text: str, max_len: int = 800) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def summarize_any(obj: Any) -> Any:
    if isinstance(obj, str):
        return summarize_text(obj)
    if isinstance(obj, list):
        return [summarize_any(v) for v in obj]
    if isinstance(obj, dict):
        return {k: summarize_any(v) for k, v in obj.items()}
    return obj


def policy_check(obj: Any) -> Tuple[str, Dict[str, str]]:
    return "ok", {}


def apply_egress_pipeline(obj: Any) -> Tuple[Any, Dict[str, str]]:
    """
    Pipeline: (redact via defaults+rulepacks if enforce)
    -> (optional summarize) -> (optional policy_check).
    Returns (processed_obj, meta_headers).
    """
    meta: Dict[str, str] = {}

    rp_reds = egress_redactions()
    all_reds = DEFAULT_REDACTIONS + rp_reds if egress_mode() == "enforce" else DEFAULT_REDACTIONS

    processed = transform_with(obj, all_reds)

    if SUMMARIZE_ENABLED:
        processed = summarize_any(processed)

    if POLICY_CHECK_ENABLED:
        status, annotations = policy_check(processed)
        meta["egress_policy_status"] = status
        for k, v in annotations.items():
            meta[f"egress_policy_{k}"] = v

    if rp_reds:
        meta["egress_rulepacks"] = "1"

    return processed, meta
