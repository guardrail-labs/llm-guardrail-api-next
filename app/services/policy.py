import uuid
from pathlib import Path
from typing import List

import yaml
from pydantic import BaseModel

from app.telemetry import metrics as tmetrics
from app.services.upipe import analyze, Decision

_RULES_PATH = Path(__file__).resolve().parent.parent / "policy" / "rules.yaml"
_rules = yaml.safe_load(_RULES_PATH.read_text(encoding="utf-8"))


class Outcome(BaseModel):
    request_id: str
    decision: str  # "allow" | "block"
    reason: str
    rule_hits: List[str]
    transformed_text: str
    policy_version: str


def _final_decision(decisions: List[Decision]) -> str:
    # For now, any detected high-severity rule ⇒ block.
    return "block" if decisions else "allow"


def _compose_reason(decisions: List[Decision]) -> str:
    if not decisions:
        return "No risk signals detected"
    ids = ", ".join(sorted({d.rule_id for d in decisions}))
    return f"High-risk rules matched: {ids}"


def evaluate_and_apply(text: str) -> Outcome:
    # 1) Analyze
    decisions: List[Decision] = analyze(text)

    # 2) Compute final decision
    decision = _final_decision(decisions)
    rule_hits = [d.rule_id for d in decisions] if decisions else []
    reason = _compose_reason(decisions)

    # 3) Transform (no-op for now)
    transformed_text = text

    # 4) Metrics
    try:
        tmetrics.inc_decision(decision)
        tmetrics.inc_rule_hits(rule_hits)
    except Exception:
        # Metrics should never break the API
        pass

    # 5) Outcome
    return Outcome(
        request_id=str(uuid.uuid4()),
        decision=decision,
        reason=reason,
        rule_hits=rule_hits,
        transformed_text=transformed_text,
        policy_version=str(_rules.get("version", "1")),
    )
