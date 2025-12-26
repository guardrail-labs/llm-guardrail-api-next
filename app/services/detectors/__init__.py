from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from app.services.intent.layer2 import Layer2Config, score_intent
from app.services.policy import apply_policies
from app.services.routing.fingerprint import fingerprint_prompt, is_near_duplicate
from app.services.routing.router import route_ingress
from app.services.text.normalize import normalize_for_matching
from app.services.text_normalization import normalize_text_for_policy

from .layer1_keywords import layer1_keyword_decisions
from .pdf_hidden import sanitize_for_downstream as pdf_sanitize_for_downstream

__all__ = ["evaluate_prompt", "normalize_text_for_policy", "pdf_sanitize_for_downstream"]


HARD_ACTIONS: Set[str] = {
    "deny",
    "block",
    "block_input_only",
    "lock",
    "execute_locked",
    "full_quarantine",
}


def evaluate_prompt(
    text: str,
    *,
    prior_prompt_fingerprint: Optional[str] = None,
    attempt: int = 0,
) -> Dict[str, Any]:
    """
    Run the core policy evaluation for ingress text and present a normalized
    result that routes can consume.

    Returns keys used by /guardrail/evaluate:
      - action: "allow" | "sanitize" | "deny" | "clarify" | "block_input_only" | ...
      - transformed_text: sanitized text (redactions applied)
      - risk_score: int score (heuristic)
      - rule_hits: list[dict] of {"tag","pattern"}
      - decisions: list[dict] (routes may extend)
      - routing: dict with routing metadata
      - clarify_message: str | None
    """
    normalized_policy = normalize_text_for_policy(text)
    res = apply_policies(text, normalized_text=normalized_policy)

    decisions = cast_list_of_dict(res.get("decisions", []))

    normalized_matching = normalize_for_matching(text)
    layer1_decisions = layer1_keyword_decisions(normalized_matching)
    decisions.extend(layer1_decisions)

    layer1_categories = [
        decision["category"]
        for decision in layer1_decisions
        if isinstance(decision.get("category"), str)
    ]

    risk_score = int(res.get("risk_score", 0))

    layer2_cfg = Layer2Config.from_settings()
    layer2_score = 0
    if layer2_cfg.enabled:
        layer2_result = score_intent(text, layer2_cfg)
        layer2_score = int(layer2_result.score)
        risk_score += layer2_score
        decisions.append(
            {
                "source": "layer2_intent",
                "score": layer2_result.score,
                "bucket_hits": layer2_result.bucket_hits,
                "pair_hits": layer2_result.pair_hits,
                "typo_hits": layer2_result.typo_hits,
                "signals": layer2_result.signals,
            }
        )

    current_fingerprint = fingerprint_prompt(text)
    near_duplicate = prior_prompt_fingerprint is not None and is_near_duplicate(
        prior_prompt_fingerprint, current_fingerprint
    )

    routing_decision = route_ingress(
        risk_score=risk_score,
        layer1_categories=layer1_categories,
        layer2_score=layer2_score,
        attempt=attempt,
        near_duplicate=near_duplicate,
    )

    action = str(res.get("action", "allow"))
    clarify_message: Optional[str] = None

    # PR1: Routing is authoritative for block_input_only (stop abuse/near-duplicates).
    # Clarify requires caller plumbing (OpenAI-compat currently treats clarify as deny).
    if action not in HARD_ACTIONS:
        if routing_decision.action.value == "block_input_only":
            action = "block_input_only"
        elif action == "clarify":
            clarify_message = routing_decision.message

    clarify_stage = (
        routing_decision.clarify_stage.value
        if routing_decision.clarify_stage is not None
        else None
    )

    return {
        "action": action,
        "transformed_text": res.get("sanitized_text", text),
        "risk_score": risk_score,
        "rule_hits": list(res.get("hits", [])),
        "decisions": decisions,
        "routing": {
            "action": routing_decision.action.value,
            "clarify_stage": clarify_stage,
            "attempt": routing_decision.attempt,
            "near_duplicate": routing_decision.near_duplicate,
        },
        "clarify_message": clarify_message,
    }


def cast_list_of_dict(val: Any) -> List[Dict[str, Any]]:
    if isinstance(val, list) and all(isinstance(x, dict) for x in val):
        return val
    return []
