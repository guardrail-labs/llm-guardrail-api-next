from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Sequence, Tuple

from app.policy.packs import AdvisoryLevel, LoadedPacks, SeverityLevel

ADVISORY_ORDER: Dict[AdvisoryLevel, int] = {
    "pass": 0,
    "flag": 1,
    "clarify": 2,
    "block": 3,
}


@dataclass(frozen=True)
class Violation:
    pack: str
    rule_id: str
    advisory: AdvisoryLevel
    severity: SeverityLevel


def evaluate_text(text: str, packs: LoadedPacks) -> Tuple[List[Violation], AdvisoryLevel]:
    """Evaluate plain text against loaded policy rules."""

    hits: List[Violation] = []
    max_action: AdvisoryLevel = "pass"

    def bump(action: AdvisoryLevel) -> None:
        nonlocal max_action
        if ADVISORY_ORDER[action] > ADVISORY_ORDER[max_action]:
            max_action = action

    lower_text = text.lower()
    for rule in packs.rules:
        if rule.pattern and rule.pattern.search(text):
            hits.append(
                Violation(
                    pack=rule.pack,
                    rule_id=rule.id,
                    advisory=rule.advisory,
                    severity=rule.severity,
                )
            )
            bump(rule.advisory)
            continue
        if rule.any_terms and _has_any_term(lower_text, rule.any_terms):
            hits.append(
                Violation(
                    pack=rule.pack,
                    rule_id=rule.id,
                    advisory=rule.advisory,
                    severity=rule.severity,
                )
            )
            bump(rule.advisory)

    return hits, max_action


def policy_headers(
    violations: Sequence[Violation], action: AdvisoryLevel
) -> Dict[str, str]:
    if not violations:
        return {}
    items = [f"{violation.pack}:{violation.rule_id}" for violation in violations]
    value = f"{','.join(items)};action={action}"
    return {"X-Guardrail-Policy": value}


def _has_any_term(text: str, terms: Iterable[str]) -> bool:
    for term in terms:
        if term.lower() in text:
            return True
    return False

