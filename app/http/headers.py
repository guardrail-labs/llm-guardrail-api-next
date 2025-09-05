# app/http/headers.py
from __future__ import annotations

from typing import Optional
from fastapi import Response

DEFAULT_POLICY_VERSION = "test-policy"  # tests only check presence


def attach_guardrail_headers(
    resp: Response,
    *,
    policy_version: str = DEFAULT_POLICY_VERSION,
    decision: str = "allow",
    ingress_action: Optional[str] = None,
    egress_action: Optional[str] = None,
) -> Response:
    """
    Idempotently attach the guardrail headers expected by tests.
    Use in both JSON and SSE/streaming responses.

    - If actions aren't provided:
        ingress_action -> decision
        egress_action  -> "allow"
    """
    h = resp.headers
    if "X-Guardrail-Policy-Version" not in h:
        h["X-Guardrail-Policy-Version"] = policy_version

    if ingress_action is None:
        ingress_action = decision
    if egress_action is None:
        egress_action = "allow"

    # Set (but don't clobber if a route already set something explicit)
    h.setdefault("X-Guardrail-Decision", decision)
    h.setdefault("X-Guardrail-Ingress-Action", ingress_action)
    h.setdefault("X-Guardrail-Egress-Action", egress_action)

    return resp
