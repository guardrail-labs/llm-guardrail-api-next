from typing import List
from uuid import uuid4

from pydantic import BaseModel

from app.config import settings
from app.services.policy_loader import get_policy
from app.services.redact import redact
from app.services.upipe import Decision, analyze
from app.telemetry import metrics as tmetrics
from app.telemetry.audit import emit_decision_event


class Outcome(BaseModel):
    request_id: str
    decision: str  # "allow" | "block"
    reason: str
    rule_hits: List[str]
    transformed_text: str
    policy_version: str


def _final_decision(decisions: List[Decision]) -> str:
    return "block" if decisions else "allow"


def _compose_reason(decisions: List[Decision]) -> str:
    if not decisions:
        return "No risk signals detected"
    ids = ", ".join(sorted({d.rule_id for d in decisions}))
    return f"High-risk rules matched: {ids}"


def _maybe_redact(text: str) -> str:
    if not settings.REDACT_SECRETS:
        return text
    result = redact(
        text,
        openai_mask=settings.REDACT_OPENAI_MASK,
        aws_mask=settings.REDACT_AWS_AKID_MASK,
        pem_mask=settings.REDACT_PEM_MASK,
    )
    for kind in result.kinds:
        try:
            tmetrics.inc_redaction(kind)
        except Exception:
            pass
    return result.text


def evaluate_and_apply(text: str) -> Outcome:
    rid = str(uuid4())

    # Load current policy (hot-reload if enabled)
    blob = get_policy()
    rules = blob.rules
    _ = rules  # reserved for future policy execution; currently uPipe drives decisions

    # 1) Analyze
    decisions: List[Decision] = analyze(text)

    # 2) Compute final decision
    decision = _final_decision(decisions)
    rule_hits = [d.rule_id for d in decisions] if decisions else []
    reason = _compose_reason(decisions)

    # 3) Transform (redact secrets if enabled)
    transformed_text = _maybe_redact(text)

    # 4) Metrics
    try:
        tmetrics.inc_decision(decision)
        tmetrics.inc_rule_hits(rule_hits)
    except Exception:
        pass

    # 5) Outcome
    outcome = Outcome(
        request_id=rid,
        decision=decision,
        reason=reason,
        rule_hits=rule_hits,
        transformed_text=transformed_text,
        policy_version=str(blob.version),
    )

    # 6) Audit (sampled JSON event)
    try:
        emit_decision_event(
            request_id=rid,
            decision=decision,
            rule_hits=rule_hits,
            reason=reason,
            transformed_text=transformed_text,
            policy_version=outcome.policy_version,
            prompt_len=len(text),
        )
    except Exception:
        pass

    return outcome

