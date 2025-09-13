from __future__ import annotations

import os
from typing import Any, Dict, Tuple

from app.services.egress.filter import transform as redact_transform

SUMMARIZE_ENABLED = os.getenv("EGRESS_SUMMARIZE_ENABLED", "0") == "1"
POLICY_CHECK_ENABLED = os.getenv("EGRESS_POLICY_CHECK_ENABLED", "0") == "1"


def summarize_text(text: str, max_len: int = 800) -> str:
    """Very simple length-capped summarizer placeholder (non-LLM)."""
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
    """Placeholder policy-check: always 'ok' with no annotations."""
    return "ok", {}


def apply_egress_pipeline(obj: Any) -> Tuple[Any, Dict[str, str]]:
    """Pipeline: redact -> (optional summarize) -> (optional policy_check)."""
    meta: Dict[str, str] = {}

    redacted = redact_transform(obj)
    processed = summarize_any(redacted) if SUMMARIZE_ENABLED else redacted

    if POLICY_CHECK_ENABLED:
        status, annotations = policy_check(processed)
        meta["egress_policy_status"] = status
        meta.update({f"egress_policy_{k}": v for k, v in annotations.items()})

    return processed, meta

