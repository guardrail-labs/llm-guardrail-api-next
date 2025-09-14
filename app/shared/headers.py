from __future__ import annotations

from typing import List, Optional

from fastapi import Response

TENANT_HEADER = "X-Tenant-ID"
BOT_HEADER = "X-Bot-ID"

DEFAULT_POLICY_VERSION = "test-policy"

def attach_guardrail_headers(
    resp: Response,
    *,
    policy_version: Optional[str] = DEFAULT_POLICY_VERSION,
    decision: str = "allow",
    ingress_action: Optional[str] = None,
    egress_action: Optional[str] = None,
    redaction_count: Optional[int] = None,
    redaction_reasons: Optional[List[str]] = None,
) -> Response:
    if ingress_action is None:
        ingress_action = decision
    if egress_action is None:
        egress_action = "allow"

    h = resp.headers
    if policy_version:
        h.setdefault("X-Guardrail-Policy-Version", policy_version)
    h.setdefault("X-Guardrail-Decision", decision)
    h.setdefault("X-Guardrail-Ingress-Action", ingress_action)
    h.setdefault("X-Guardrail-Egress-Action", egress_action)

    if redaction_count is not None:
        h["X-Guardrail-Redactions"] = str(int(max(0, redaction_count)))
    if redaction_reasons:
        h["X-Guardrail-Redaction-Reasons"] = ",".join(redaction_reasons[:10])

    return resp
