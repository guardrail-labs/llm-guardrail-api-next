from __future__ import annotations

import json
import logging
from typing import Iterable

from app.config import get_settings

logger = logging.getLogger("guardrail_audit")


def emit_decision_event(
    *,
    request_id: str,
    decision: str,
    rule_hits: Iterable[str],
    reason: str,
    policy_version: str,
    prompt_text: str,
) -> None:
    """
    Emit a single JSON audit line with a bounded snippet from the prompt text.
    Respects AUDIT_MAX_TEXT_CHARS from settings.
    """
    s = get_settings()
    max_chars = int(getattr(s, "AUDIT_MAX_TEXT_CHARS", 200))
    snippet = prompt_text[: max(0, max_chars)]
    truncated = len(prompt_text) > max_chars

    event = {
        "event": "guardrail_decision",
        "request_id": request_id,
        "decision": decision,
        "rule_hits": list(rule_hits),
        "reason": reason,
        "policy_version": policy_version,
        "prompt_len": len(prompt_text),
        "snippet_len": len(snippet),
        "snippet": snippet,
        "snippet_truncated": truncated,
        "service": getattr(s, "SERVICE_NAME", "llm-guardrail-api-next"),
        "env": getattr(s, "ENV", "dev"),
    }
    logger.info(json.dumps(event, ensure_ascii=False))
