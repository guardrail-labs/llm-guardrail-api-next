from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

# Reuse ingress sanitization helpers for egress redactions
from app.services.policy import sanitize_text

# Minimal "hard deny" marker: if an LLM tries to output a private key envelope,
# we deny instead of attempting to redact, to avoid partial leakage.
_PRIV_KEY_BOUNDS = re.compile(
    r"(?:-----BEGIN (?:.*)PRIVATE KEY-----|-----END (?:.*)PRIVATE KEY-----)"
)

# Example future expansion:
# - Add content classifiers for HIPAA/GDPR/FERPA categories.
# - Map matched categories to "policy:deny:*" or allow-with-redaction.


def egress_check(text: str, debug: bool = False) -> Tuple[Dict[str, Any], List[str]]:
    """
    Evaluate outbound LLM text. Return (response_payload, debug_messages).

    Decision policy (v1):
    - If private key envelope markers are present -> action="deny"
      (policy:deny:private_key_envelope)
    - Else apply redactions via sanitize_text():
      * If only redactions applied -> action="allow"
      * Families reflect which rule families were hit (secrets:*, pi:*, payload:*)
    """
    debug_msgs: List[str] = []
    payload: Dict[str, Any]  # declared once to avoid mypy no-redef

    # 1) Hard deny policy checks first (expandable)
    if _PRIV_KEY_BOUNDS.search(text or ""):
        families = ["policy:deny:*"]
        payload = {
            "action": "deny",
            "text": "",
            "rule_hits": families,
            "redactions": None,
        }
        if debug:
            debug_msgs.append("Denied due to private key envelope markers.")
        return payload, debug_msgs

    # 2) Otherwise, sanitize & allow (contract: allow when only redactions happen)
    sanitized, families, redaction_count, debug_matches = sanitize_text(text, debug=debug)

    payload = {
        "action": "allow",
        "text": sanitized,
        "rule_hits": families or None,
        "redactions": redaction_count or None,
    }

    if debug and debug_matches:
        debug_msgs.append(f"Applied {redaction_count} redactions at egress.")
    return payload, debug_msgs
