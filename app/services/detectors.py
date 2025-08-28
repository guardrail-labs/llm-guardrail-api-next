from __future__ import annotations

from typing import Any, Dict, List

from app.services import policy


def evaluate_prompt(text: str) -> Dict[str, Any]:
    """
    Run the base policy over the prompt.
    Returns:
      {
        "action": "allow|sanitize|clarify|deny",
        "risk_score": int,
        "transformed_text": str,
        "rule_hits": [ {tag, pattern}, ... ],
        "redactions": int,
        "decisions": [ ... ]   # human-readable decision trail
      }
    """
    result = policy.apply_policies(text)
    decisions: List[Dict[str, Any]] = []

    # Record rule hits
    for h in result.get("hits", []):
        decisions.append({"type": "rule_hit", "tag": h.get("tag"), "pattern": h.get("pattern")})

    # Record redaction event if any
    if result.get("redactions", 0):
        decisions.append({"type": "redaction", "changed": True, "count": result["redactions"]})

    return {
        "action": result["action"],
        "risk_score": int(result["risk_score"]),
        "transformed_text": str(result["sanitized_text"]),
        "rule_hits": list(result.get("hits", [])),
        "redactions": int(result.get("redactions", 0)),
        "decisions": decisions,
    }

