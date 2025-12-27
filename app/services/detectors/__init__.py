from __future__ import annotations

from typing import Any, Dict, List

from app import settings
from app.services.clarify_routing import REFUSAL_MESSAGE, stage_message, track_attempt
from app.services.intent.layer2 import Layer2Config, score_intent
from app.services.policy import apply_policies
from app.services.text.normalize import normalize_for_matching
from app.services.text_normalization import normalize_text_for_policy
from app.services.verifier import content_fingerprint

from .layer1_keywords import layer1_keyword_decisions
from .pdf_hidden import sanitize_for_downstream as pdf_sanitize_for_downstream

__all__ = ["evaluate_prompt", "normalize_text_for_policy", "pdf_sanitize_for_downstream"]


def evaluate_prompt(text: str) -> Dict[str, Any]:
    """
    Run the core policy evaluation for ingress text and present a normalized
    result that routes can consume.

    Returns keys used by /guardrail/evaluate:
      - action: "allow" | "clarify" | "block_input_only" | "verify_intent"
      - transformed_text: sanitized text (redactions applied)
      - risk_score: int score (heuristic)
      - rule_hits: list[dict] of {"tag","pattern"}
      - decisions: list[dict] (empty here; routes may extend)
      - prompt_fingerprint: stable hash for attempts/near-duplicate detection
      - near_duplicate: bool for near-duplicate input
      - attempt_count: int for bounded clarify attempts
      - clarify_message: str | None
      - incident_id: str (empty when not issued)
    """
    normalized_policy = normalize_text_for_policy(text)
    res = apply_policies(text, normalized_text=normalized_policy)
    decisions = cast_list_of_dict(res.get("decisions", []))
    normalized_matching = normalize_for_matching(text)
    decisions.extend(layer1_keyword_decisions(normalized_matching))
    risk_score = int(res.get("risk_score", 0))
    rule_hits = list(res.get("hits", []))
    base_action = str(res.get("action", "allow"))
    if base_action in {"deny", "block"}:
        base_action = "block_input_only"
    elif base_action == "sanitize":
        base_action = "allow"
    prompt_fp = content_fingerprint(text)
    has_gray_hit = any(hit.get("tag") == "gray" for hit in rule_hits if isinstance(hit, dict))
    explicit_clarify = any(
        hit.get("action") == "clarify" and hit.get("tag") != "gray"
        for hit in rule_hits
        if isinstance(hit, dict)
    )
    clarify_candidate = base_action == "clarify"
    attempt_count, near_duplicate = track_attempt(prompt_fp, increment=clarify_candidate)
    clarify_stage = 2 if near_duplicate or attempt_count > 1 else 1
    clarify_message = stage_message(clarify_stage) if clarify_candidate else None
    refusal_message = None
    action = base_action
    if clarify_candidate and has_gray_hit and not settings.ENABLE_INGRESS_CLARIFY_ROUTING:
        action = "allow"
    elif action == "clarify" and settings.ENABLE_INGRESS_CLARIFY_ROUTING:
        if attempt_count >= settings.MAX_CLARIFY_ATTEMPTS:
            action = "block_input_only"
            clarify_message = None
            refusal_message = REFUSAL_MESSAGE
    if action != "clarify":
        clarify_message = None

    layer2_cfg = Layer2Config.from_settings()
    if layer2_cfg.enabled:
        layer2_result = score_intent(text, layer2_cfg)
        risk_score += layer2_result.score
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
    return {
        "action": action,
        "clarify_message": clarify_message,
        "refusal_message": refusal_message,
        "transformed_text": res.get("sanitized_text", text),
        "risk_score": risk_score,
        "rule_hits": rule_hits,
        "prompt_fingerprint": prompt_fp,
        "near_duplicate": near_duplicate,
        "attempt_count": attempt_count,
        "incident_id": "",
        "routing_metadata": {
            "clarify_stage": clarify_stage if clarify_candidate else None,
            "clarify_enabled": settings.ENABLE_INGRESS_CLARIFY_ROUTING,
            "max_attempts": settings.MAX_CLARIFY_ATTEMPTS,
            "would_clarify": bool(clarify_candidate),
            "explicit_clarify": bool(explicit_clarify),
        },
        "decisions": decisions,
    }


def cast_list_of_dict(val: Any) -> List[Dict[str, Any]]:
    if isinstance(val, list) and all(isinstance(x, dict) for x in val):
        return val  # already normalized
    return []
