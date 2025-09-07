"""
Lightweight validator for decision trace payloads (UI consumption).
Avoids external jsonschema dep; checks structure & types.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

_REQUIRED_TOP_LEVEL = ("text", "action", "debug")
_OPTIONAL_TOP_LEVEL = ("rule_hits", "redactions", "trace", "incident_id")


def validate_trace_payload(doc: Dict[str, Any]) -> Tuple[bool, List[str]]:
    errs: List[str] = []
    for k in _REQUIRED_TOP_LEVEL:
        if k not in doc:
            errs.append(f"missing:{k}")
    if "rule_hits" in doc and not isinstance(doc["rule_hits"], list):
        errs.append("rule_hits:not_list")
    if "redactions" in doc and not isinstance(doc["redactions"], dict):
        errs.append("redactions:not_dict")
    if "trace" in doc and not isinstance(doc["trace"], list):
        errs.append("trace:not_list")
    if "debug" in doc and not isinstance(doc["debug"], dict):
        errs.append("debug:not_dict")
    return (len(errs) == 0, errs)
