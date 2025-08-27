from typing import List
from uuid import uuid4

from pydantic import BaseModel
from uuid import uuid4
from typing import List

from pydantic import BaseModel

from app.config import get_settings
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


def _final_decision(any_hits: bool) -> str:
    return "block" if any_hits else "allow"


def _compose_reason(rule_ids: List[str]) -> str:
    if not rule_ids:
        return "No risk signals detected"
    ids = ", ".join(sorted(set(rule_ids)))
    return f"High-risk rules matched: {ids}"


def _maybe_redact(text: str) -> str:
    s = get_settings()
    if not s.REDACT_SECRETS:
        return text
    result = redact(
        text,
        openai_mask="[REDACTED:OPENAI_KEY]",
        aws_mask="[REDACTED:AWS_ACCESS_KEY_ID]",
        pem_mask="[REDACTED:PRIVATE_KEY]",
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

    # 1) Analyze via uPipe (builtin heuristics)
    pipe_decisions: List[Decision] = analyze(text)
    rule_ids: List[str] = [d.rule_id for d in pipe_decisions]

    # 2) Evaluate policy-driven deny regex (from rules.yaml)
    for rid_cfg, pattern in blob.deny_compiled:
        if pattern.search(text):
            rule_ids.append(f"policy:deny:{rid_cfg}")

    any_hits = bool(rule_ids)

    # 3) Transform (redact secrets if enabled)
    transformed_text = _maybe_redact(text)

    # 4) Metrics
    try:
        tmetrics.inc_decision(_final_decision(any_hits))
        tmetrics.inc_rule_hits(rule_ids)
    except Exception:
        pass

    # 5) Outcome
    outcome = Outcome(
        request_id=rid,
        decision=_final_decision(any_hits),
        reason=_compose_reason(rule_ids),
        rule_hits=rule_ids,
        transformed_text=transformed_text,
        policy_version=str(blob.version),
    )

    # 6) Audit (sampled JSON event)
    try:
        emit_decision_event(
            request_id=rid,
            decision=outcome.decision,
            rule_hits=rule_ids,
            reason=outcome.reason,
            transformed_text=transformed_text,
            policy_version=outcome.policy_version,
            prompt_len=len(text),
        )
    except Exception:
        pass

    return outcome

