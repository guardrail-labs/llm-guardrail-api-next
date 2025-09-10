from __future__ import annotations

import os
from typing import Any, Dict, Optional, Tuple

# ---------------------------------------------------------------------
# Feature flag
# ---------------------------------------------------------------------


def _get_mode() -> str:
    """
    VERIFIER_HARDENED_MODE:
      - "off"      => do nothing (default if var unset/empty/unknown)
      - "headers"  => call hardened verifier; attach headers ONLY
      - "enforce"  => call hardened verifier; map to action and enforce
    """
    v = (os.getenv("VERIFIER_HARDENED_MODE") or "").strip().lower()
    if v in {"headers", "enforce", "off"}:
        return v
    return "off"


# ---------------------------------------------------------------------
# Header + action normalization
# ---------------------------------------------------------------------


def _normalize_headers(
    outcome: Dict[str, Any], hdrs_in: Optional[Dict[str, Any]]
) -> Dict[str, str]:
    """
    Build stable X-Guardrail-* headers from whatever the hardened verifier returns.
    """
    hdrs: Dict[str, str] = {}
    if isinstance(hdrs_in, dict):
        for k, v in list(hdrs_in.items()):
            try:
                hdrs.setdefault(str(k), str(v))
            except Exception:
                # Drop non-serializable header values
                pass

    status = str(
        outcome.get("status", outcome.get("outcome", "error")) or "error"
    ).lower()
    hdrs.setdefault("X-Guardrail-Outcome", status)

    reason = outcome.get("reason")
    if isinstance(reason, str) and reason:
        hdrs.setdefault("X-Guardrail-Reason", reason[:512])

    # Prefer explicit source header if already present; otherwise synthesize.
    if "X-Guardrail-Decision-Source" not in hdrs:
        used_fallback = bool(outcome.get("used_fallback", False))
        src = "verifier-fallback" if used_fallback else "verifier-live"
        hdrs["X-Guardrail-Decision-Source"] = src

    return hdrs


def _map_to_action(status: str, *, direction: str) -> Optional[str]:
    """
    Conservative mapping used only when VERIFIER_HARDENED_MODE='enforce'.
    Returns an action override or None to keep current action.
    """
    if direction == "ingress":
        if status == "safe":
            return "allow"
        if status == "unsafe":
            return "deny"
        if status == "ambiguous":
            return "clarify"
        return None
    # egress: escalate only clear unsafe; let redactors handle ambiguous
    if status == "unsafe":
        return "deny"
    return None


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
    latency_budget_ms: Optional[int] = 1200,
    token_budget: Optional[int] = 12000,
) -> Tuple[Optional[str], Dict[str, str]]:
    """
    Returns (maybe_action_override, headers).

    - In "headers" mode, action_override is None (no behavior change), but headers
      include decision source/outcome/reason if available.
    - In "enforce" mode, action_override may be "allow" | "deny" | "clarify".
    - In "off" mode, returns (None, {}).

    Calls the async hardened verifier as: verify_intent_hardened(text, context)
    and expects (outcome_dict, headers_dict).
    """
    mode = _get_mode()
    if mode == "off":
        return None, {}

    try:
        # app/services/verifier/__init__.py exposes verify_intent_hardened
        from app.services.verifier import verify_intent_hardened  # type: ignore
    except Exception:
        return None, {}

    # Build the context object expected by this codebase.
    ctx: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "bot_id": bot_id,
        "family": family or "general",
        "direction": direction,
        "latency_budget_ms": latency_budget_ms,
        "token_budget": token_budget,
    }

    try:
        # Await the coroutine and accept the canonical shape: (outcome, headers)
        out_obj, v_headers_any = await verify_intent_hardened(text, ctx)  # type: ignore[func-returns-value]
        outcome = out_obj if isinstance(out_obj, dict) else {}
        hdrs = _normalize_headers(outcome, v_headers_any if isinstance(v_headers_any, dict) else {})

        status = hdrs.get("X-Guardrail-Outcome", "error").lower()

        if mode == "enforce":
            override = _map_to_action(status, direction=direction)
            return override, hdrs

        # headers mode
        return None, hdrs

    except Exception:
        # Any issues -> silent no-op to avoid behavior regressions
        return None, {}
