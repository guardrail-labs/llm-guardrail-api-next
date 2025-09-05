# app/shared/headers.py
from __future__ import annotations
from typing import Optional
from fastapi import Response

TENANT_HEADER = "X-Tenant-ID"
BOT_HEADER = "X-Bot-ID"

DEFAULT_POLICY_VERSION = "test-policy"  # tests only check presence

def attach_guardrail_headers(
    resp: Response,
    *,
    policy_version: str = DEFAULT_POLICY_VERSION,
    decision: str = "allow",
    ingress_action: Optional[str] = None,
    egress_action: Optional[str] = None,
) -> Response:
    if ingress_action is None:
        ingress_action = decision
    if egress_action is None:
        egress_action = "allow"

    h = resp.headers
    h.setdefault("X-Guardrail-Policy-Version", policy_version)
    h.setdefault("X-Guardrail-Decision", decision)
    h.setdefault("X-Guardrail-Ingress-Action", ingress_action)
    h.setdefault("X-Guardrail-Egress-Action", egress_action)
    return resp
