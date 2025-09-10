from __future__ import annotations

import os
from typing import Dict, Optional, Tuple


def _get_mode() -> str:
    """
    VERIFIER_HARDENED_MODE:
      - "off"      => do nothing (default if var unset/empty/unknown)
      - "headers"  => call hardened verifier; attach headers ONLY (no behavior change)
      - "enforce"  => call hardened verifier; map to action and enforce
    """
    v = (os.getenv("VERIFIER_HARDENED_MODE") or "").strip().lower()
    if v in {"headers", "enforce", "off"}:
        return v
    return "off"


def maybe_verify_and_headers(
    *,
    text: str,
    direction: str,       # "ingress" | "egress"
    tenant_id: Optional[str],
    bot_id: Optional[str],
    family: Optional[str],
    latency_budget_ms: Optional[int] = 1200,
    token_budget: Optional[int] = 12000,
) -> Tuple[Optional[str], Dict[str, str]]:
    """
    Returns (maybe_action_override, headers).

    - In "headers" mode, action_override is None (no behavior change), but headers
      include decision source/outcome/reason if available.
    - In "enforce" mode, action_override may be "allow" | "deny" | "clarify" etc.
    - In "off" mode, returns (None, {}).
    """
    mode = _get_mode()
    if mode == "off":
        return None, {}

    try:
        from app.services.verifier import verify_intent_hardened  # type: ignore
    except Exception:
        return None, {}

    try:
        outcome, used_fallback, reason, v_headers = verify_intent_hardened(
            text=text,
            tenant_id=tenant_id,
            bot_id=bot_id,
            family=(family or "general"),
            latency_budget_ms=latency_budget_ms,
            token_budget=token_budget,
            direction=direction,
        )
        hdrs: Dict[str, str] = dict(v_headers or {})
        hdrs.setdefault(
            "X-Guardrail-Decision-Source",
            "verifier-fallback" if used_fallback else "verifier-live",
        )
        norm_outcome = str(outcome or "").lower() or "error"
        hdrs.setdefault("X-Guardrail-Outcome", norm_outcome)
        if reason:
            hdrs.setdefault("X-Guardrail-Reason", str(reason)[:512])

        if mode == "enforce":
            if direction == "ingress":
                if norm_outcome == "safe":
                    return "allow", hdrs
                if norm_outcome == "unsafe":
                    return "deny", hdrs
                if norm_outcome == "ambiguous":
                    return "clarify", hdrs
                return None, hdrs
            else:
                if norm_outcome == "unsafe":
                    return "deny", hdrs
                return None, hdrs

        return None, hdrs
    except Exception:
        return None, {}
