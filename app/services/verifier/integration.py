from __future__ import annotations

import os
from typing import Any, Dict, Optional, Tuple, cast

from app.services import runtime_flags
from app.telemetry.metrics import inc_verifier_outcome


def error_fallback_action() -> str:
    v = runtime_flags.get("verifier_error_fallback")
    if isinstance(v, str) and v in {"allow", "deny", "clarify"}:
        return v
    return "allow"

# ---------------------------------------------------------------------
# Env helpers
# ---------------------------------------------------------------------


def _get_mode() -> str:
    v = (os.getenv("VERIFIER_HARDENED_MODE") or "headers").strip().lower()
    if v in {"off", "headers", "enforce"}:
        return v
    return "headers"


def _get_default_action() -> str:
    v = (os.getenv("VERIFIER_DEFAULT_ACTION") or "allow").strip().lower()
    if v in {"allow", "deny", "clarify"}:
        return v
    return "allow"


# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------


async def maybe_verify_and_headers(
    *,
    text: str,
    direction: str,  # "ingress" | "egress"
    tenant_id: Optional[str],
    bot_id: Optional[str],
    family: Optional[str],
    latency_budget_ms: Optional[int] = None,
    token_budget: Optional[int] = None,
) -> Tuple[Optional[str], Dict[str, str]]:
    """Call hardened verifier and return (action, headers).

    On any failure or if disabled, returns (None, {}).
    """

    mode = _get_mode()
    if mode == "off":
        return None, {}

    try:
        from app.services.verifier import verify_intent_hardened
    except Exception:
        return None, {}

    ctx: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "bot_id": bot_id,
        "family": family or "general",
        "direction": direction,
        "latency_budget_ms": latency_budget_ms,
        "token_budget": token_budget,
    }

    default_action = _get_default_action()
    vfunc: Any = verify_intent_hardened
    out_obj, hdr_in = cast(
        Tuple[Dict[str, Any], Dict[str, Any]], await vfunc(text, ctx)
    )

    outcome = out_obj if isinstance(out_obj, dict) else {}
    headers_in = hdr_in if isinstance(hdr_in, dict) else {}

    status = str(outcome.get("status", "")).lower()
    reason = outcome.get("reason")
    provider = str(
        outcome.get("provider")
        or headers_in.get("X-Guardrail-Verifier")
        or "unknown"
    )

    if status == "safe":
        decision = "allow"
        source = "verifier-live"
    elif status == "unsafe":
        decision = "deny"
        source = "verifier-live"
    elif status == "ambiguous":
        decision = "clarify"
        source = "verifier-live"
    else:
        decision = default_action
        source = "verifier-fallback"

    inc_verifier_outcome(provider, decision if source == "verifier-live" else "fallback")

    headers: Dict[str, str] = {}
    for k, v in headers_in.items():
        try:
            headers[str(k)] = str(v)
        except Exception:
            pass

    headers["X-Guardrail-Decision"] = decision
    headers["X-Guardrail-Decision-Source"] = source
    headers["X-Guardrail-Mode"] = "live" if source == "verifier-live" else "fallback"
    if isinstance(reason, str) and reason:
        headers["X-Guardrail-Reason"] = reason[:512]
    if "X-Guardrail-Verifier" not in headers and provider:
        headers["X-Guardrail-Verifier"] = provider

    return decision, headers

