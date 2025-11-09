from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class Lint:
    severity: str  # "error" | "warn" | "info"
    code: str  # e.g., "duplicate_id", "regex_compile_error", ...
    message: str
    path: str  # JSONPath-ish pointer, e.g., "rules.redact[3]"
    rule_id: Optional[str] = None


def _iter_redact_rules(policy: Dict[str, Any]) -> List[Tuple[int, Dict[str, Any]]]:
    rules = ((policy or {}).get("rules") or {}).get("redact") or []
    out: List[Tuple[int, Dict[str, Any]]] = []
    if isinstance(rules, list):
        for i, r in enumerate(rules):
            if isinstance(r, dict):
                out.append((i, r))
    return out


# Heuristic: nested quantifier where inside the group there is a + or * near the end.
_nested_inner = re.compile(r"\((?:(?:[^()\\]|\\.)*?[\*\+](?:[^()\\]|\\.)*?)\)\+")
_greedy_any = re.compile(r"\.\*")  # greedy dot-star


def lint_policy(policy: Dict[str, Any]) -> List[Lint]:
    issues: List[Lint] = []
    # 0) Structure
    if not isinstance(policy, dict):
        return [Lint("error", "invalid_policy", "Policy must be a mapping", "$")]

    rules_seen_ids: Dict[str, int] = {}
    patterns_seen: Dict[str, List[int]] = {}

    rules_obj = policy.get("rules") if isinstance(policy, dict) else None
    redact = rules_obj.get("redact") if isinstance(rules_obj, dict) else None
    if redact is None:
        issues.append(Lint("warn", "missing_redact", "No rules.redact present", "rules"))
        return issues
    if not isinstance(redact, list):
        issues.append(
            Lint("error", "invalid_redact_type", "rules.redact must be a list", "rules.redact")
        )
        return issues
    if len(redact) == 0:
        issues.append(Lint("warn", "empty_redact", "rules.redact is empty", "rules.redact"))

    for idx, r in _iter_redact_rules(policy):
        path = f"rules.redact[{idx}]"
        rid = r.get("id")
        patt = r.get("pattern")
        # 1) required fields
        if not isinstance(rid, str) or not rid.strip():
            issues.append(Lint("error", "missing_id", "Rule is missing a non-empty id", path))
            continue
        if not isinstance(patt, str) or not patt.strip():
            issues.append(
                Lint(
                    "error",
                    "missing_pattern",
                    "Rule is missing a non-empty pattern",
                    path,
                    rule_id=rid,
                )
            )
            continue

        # 2) duplicate ids (within merged policy)
        if rid in rules_seen_ids:
            first = rules_seen_ids[rid]
            issues.append(
                Lint(
                    "error",
                    "duplicate_id",
                    f"Duplicate rule id '{rid}' (first at rules.redact[{first}])",
                    path,
                    rule_id=rid,
                )
            )
        else:
            rules_seen_ids[rid] = idx

        # 3) compile regex (basic validation)
        try:
            re.compile(patt)
        except re.error as e:
            issues.append(
                Lint(
                    "error",
                    "regex_compile_error",
                    f"Regex failed to compile: {e}",
                    path,
                    rule_id=rid,
                )
            )
            continue

        # 4) duplicate exact pattern text across different ids (warning)
        patterns_seen.setdefault(patt, []).append(idx)

        # 5) overbroad heuristics
        if _greedy_any.search(patt) and "?" not in patt:
            issues.append(
                Lint(
                    "warn",
                    "overbroad_dotstar",
                    "Greedy '.*' may cause over-matching; prefer bounded or lazy quantifier",
                    path,
                    rule_id=rid,
                )
            )

        # 6) nested quantifier heuristic (risk of catastrophic backtracking)
        if _nested_inner.search(patt):
            issues.append(
                Lint(
                    "warn",
                    "nested_quantifiers",
                    "Nested quantifiers (e.g., (…+)+) can cause excessive backtracking",
                    path,
                    rule_id=rid,
                )
            )

        # 7) boundary guidance: common PII often needs word boundaries
        if (
            "email" in rid or "ssn" in rid or "credit" in rid or "phone" in rid
        ) and "\\b" not in patt:
            issues.append(
                Lint(
                    "info",
                    "missing_word_boundary",
                    "Consider adding \\b word boundaries to reduce false positives",
                    path,
                    rule_id=rid,
                )
            )

        # 8) flags type check if present
        flags = r.get("flags")
        if flags is not None and not isinstance(flags, (str, int, list)):
            issues.append(
                Lint(
                    "warn",
                    "invalid_flags_type",
                    "flags should be str|int|list",
                    path,
                    rule_id=rid,
                )
            )

    # finalize duplicates by pattern
    for patt, idxs in patterns_seen.items():
        if len(idxs) > 1:
            examples = ", ".join(f"rules.redact[{i}]" for i in idxs[:3])
            issues.append(
                Lint(
                    "warn",
                    "duplicate_pattern",
                    f"Same regex text used in multiple rules ({examples})",
                    "rules.redact",
                )
            )

    return issues


__all__ = ["Lint", "lint_policy"]
