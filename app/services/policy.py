from __future__ import annotations

import re
import threading
from typing import Dict, List, Pattern, Tuple, Any

# Thread-safe counters and rule storage
_RULE_LOCK = threading.RLock()
_REDACTIONS_TOTAL = 0.0
_RULES_VERSION = "1"

# Compiled rule caches (filled by _compile_rules)
_RULES: Dict[str, List[Pattern[str]]] = {
    "secrets": [],
    "unsafe": [],
    "gray": [],
}
# Redaction patterns: (compiled_regex, replacement_label)
_REDACTIONS: List[Tuple[Pattern[str], str]] = []


def _compile_rules() -> None:
    """
    Compile in-memory rules. No YAML or external deps in base.
    Enterprise repo can override/extend this module.
    """
    global _RULES, _REDACTIONS
    with _RULE_LOCK:
        # --- Secrets (sample subset) ---
        secrets: List[Pattern[str]] = [
            re.compile(r"sk-[A-Za-z0-9]{16,}"),             # OpenAI-style key
            re.compile(r"AKIA[0-9A-Z]{16}"),                # AWS access key id
        ]
        pk_marker = r"(?:-----BEGIN PRIVATE KEY-----|-----END PRIVATE KEY-----)"
        secrets.append(re.compile(pk_marker))

        # --- Unsafe (clear policy violations / wrongdoing intent) ---
        unsafe: List[Pattern[str]] = [
            re.compile(r"\b(hack|exploit).*(wifi|router|wpa2)", re.I),
            re.compile(r"\b(make|build).*(bomb|weapon|explosive)", re.I),
        ]

        # --- Gray area (likely jailbreaks / intent unclear) ---
        gray: List[Pattern[str]] = [
            re.compile(r"\bignore\s+previous\s+instructions\b", re.I),
            re.compile(r"\bpretend\s+to\s+be\s+DAN\b", re.I),
            re.compile(r"\bthis\s+is\s+for\s+education\s+only\b", re.I),
        ]

        _RULES = {"secrets": secrets, "unsafe": unsafe, "gray": gray}

        # Redactions: map to labels for auditability
        _REDACTIONS = [
            (re.compile(r"sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ"), "[REDACTED:OPENAI_KEY]"),
            (re.compile(r"sk-[A-Za-z0-9]{16,}"), "[REDACTED:OPENAI_KEY]"),
            (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED:AWS_ACCESS_KEY_ID]"),
            (re.compile(pk_marker), "[REDACTED:PRIVATE_KEY]"),
        ]


# Initial compile on import
_compile_rules()


def reload_rules() -> Dict[str, Any]:
    """Recompile rules. Kept for backward-compat with callers."""
    _compile_rules()
    loaded = sum(len(v) for v in _RULES.values())
    return {"policy_version": _RULES_VERSION, "rules_loaded": loaded}


# Some code may import this older alias.
force_reload = reload_rules


def get_redactions_total() -> float:
    return float(_REDACTIONS_TOTAL)


def current_rules_version() -> str:
    return _RULES_VERSION


def _apply_redactions(text: str) -> Tuple[str, int]:
    """Apply redaction patterns to text; return (sanitized_text, count)."""
    global _REDACTIONS_TOTAL
    count = 0
    out = text
    for rx, label in _REDACTIONS:
        # Replace all occurrences while keeping line length reasonable
        new = re.sub(rx, label, out)
        if new != out:
            # naive count increment: if changed, count at least one
            count += 1
            out = new
    if count:
        with _RULE_LOCK:
            _REDACTIONS_TOTAL += float(count)
    return out, count


def rule_hits(text: str) -> List[Dict[str, Any]]:
    """Return a list of rule hits with lightweight tagging."""
    hits: List[Dict[str, Any]] = []
    for tag, patterns in _RULES.items():
        for rx in patterns:
            if rx.search(text):
                hits.append({"tag": tag, "pattern": rx.pattern})
    return hits


def score_and_decide(
    text: str, hits: List[Dict[str, Any]]
) -> Tuple[str, int]:
    """
    Simple scoring heuristic:
      - unsafe hit: +100 (deny)
      - secret hit: +50 (sanitize)
      - gray hit: +40 (clarify if no unsafe)
    Decision order:
      1) unsafe -> deny
      2) secrets only -> sanitize
      3) gray -> clarify
      4) else -> allow
    Returns (action, risk_score)
    """
    score = 0
    tags = {h.get("tag") for h in hits}

    if "unsafe" in tags:
        score += 100
        return "deny", score

    if "secrets" in tags:
        score += 50
        return "sanitize", score

    if "gray" in tags:
        score += 40
        return "clarify", score

    return "allow", score


def apply_policies(text: str) -> Dict[str, Any]:
    """
    Full ingress policy pass for base:
      - detect rule hits
      - score & choose action
      - apply redactions (if any)
    """
    hits = rule_hits(text)
    action, risk = score_and_decide(text, hits)
    sanitized, redactions = _apply_redactions(text)
    return {
        "action": action,
        "risk_score": risk,
        "sanitized_text": sanitized,
        "redactions": redactions,
        "hits": hits,
    }

