from __future__ import annotations

from typing import Any, Dict, List

from app.services.policy import apply_policies
from app.services.text_normalization import normalize_text_for_policy

from .pdf_hidden import sanitize_for_downstream as pdf_sanitize_for_downstream

__all__ = ["evaluate_prompt", "normalize_text_for_policy", "pdf_sanitize_for_downstream"]


def evaluate_prompt(text: str) -> Dict[str, Any]:
    """
    Run the core policy evaluation for ingress text and present a normalized
    result that routes can consume.

    Returns keys used by /guardrail/evaluate:
      - action: "allow" | "sanitize" | "deny" | "clarify"
      - transformed_text: sanitized text (redactions applied)
      - risk_score: int score (heuristic)
      - rule_hits: list[dict] of {"tag","pattern"}
      - decisions: list[dict] (empty here; routes may extend)
    """
    normalized = normalize_text_for_policy(text)
    res = apply_policies(text, normalized_text=normalized)
    return {
        "action": res.get("action", "allow"),
        "transformed_text": res.get("sanitized_text", text),
        "risk_score": int(res.get("risk_score", 0)),
        "rule_hits": list(res.get("hits", [])),
        "decisions": cast_list_of_dict(res.get("decisions", [])),
    }


def cast_list_of_dict(val: Any) -> List[Dict[str, Any]]:
    if isinstance(val, list) and all(isinstance(x, dict) for x in val):
        return val  # already normalized
    return []
