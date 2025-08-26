import uuid
import yaml
from pathlib import Path
from pydantic import BaseModel
from app.services.upipe import analyze, Decision

_RULES_PATH = Path(__file__).resolve().parent.parent / "policy" / "rules.yaml"
_rules = yaml.safe_load(_RULES_PATH.read_text(encoding="utf-8"))

class Outcome(BaseModel):
    request_id: str
    decision: str
    reason: str
    rule_hits: list[str]
    transformed_text: str
    policy_version: str

def evaluate_and_apply(text: str) -> Outcome:
    # 1) analyze → rule candidates
    decisions: list[Decision] = analyze(text)

    # 2) trivial policy: always allow (starter)
    rule_hits = [d.rule_id for d in decisions] if decisions else ["allow-all"]
    decision = "allow"
    reason = "Starter policy allows all; replace with real policy."
    transformed_text = text  # no-op

    return Outcome(
        request_id=str(uuid.uuid4()),
        decision=decision,
        reason=reason,
        rule_hits=rule_hits,
        transformed_text=transformed_text,
        policy_version=str(_rules.get("version", "1")),
    )
