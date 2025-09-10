from __future__ import annotations
import os
import inspect
from typing import Any, Dict, Optional, Tuple, cast

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


def _normalize_headers(outcome: Dict[str, Any], hdrs_in: Optional[Dict[str, Any]]) -> Dict[str, str]:
    """
    Build stable X-Guardrail-* headers from whatever the hardened verifier returns.
    We avoid strong typing assumptions and cast to strings defensively.
    """
    hdrs: Dict[str, str] = {}
    if isinstance(hdrs_in, dict):
        # Coerce incoming headers to str-str (dropping non-serializable values)
        for k, v in list(hdrs_in.items()):
            try:
                hdrs.setdefault(str(k), str(v))
            except Exception:
                continue

    status = str(outcome.get("status", outcome.get("outcome", "error")) or "error").lower()
    hdrs.setdefault("X-Guardrail-Outcome", status)

    reason = outcome.get("reason")
    if isinstance(reason, str) and reason:
        hdrs.setdefault("X-Guardrail-Reason", reason[:512])

    # Prefer an explicit source header if provider already gave one
    if "X-Guardrail-Decision-Source" not in hdrs:
        used_fallback = bool(outcome.get("used_fallback", False))
        hdrs["X-Guardrail-Decision-Source"] = "verifier-fallback" if used_fallback else "verifier-live"

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
    else:
        # egress: only escalate clear unsafe; let redactors handle ambiguous
        if status == "unsafe":
            return "deny"
        return None


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
    - In "enforce" mode, action_override may be "allow" | "deny" | "clarify".
    - In "off" mode, returns (None, {}).

    Note: We DO NOT assume the hardened verifier's signature beyond accepting `text`.
    If the function is async, we bail (no-op) to avoid awaiting from a sync context.
    """
    mode = _get_mode()
    if mode == "off":
        return None, {}

    try:
        from app.services.verifier import verify_intent_hardened  # dynamic import; typing: Any
    except Exception:
        return None, {}

    # If the provider is async, skip (our routes call us from sync context).
    if inspect.iscoroutinefunction(verify_intent_hardened):
        return None, {}

    try:
        # Be liberal in what we accept:
        # - Some implementations may use verify_intent_hardened(text)
        # - Others may support named arg text=...
        try:
            res: Any = verify_intent_hardened(text)  # type: ignore[call-arg]
        except TypeError:
            res = verify_intent_hardened(text=text)  # type: ignore[call-arg]

        outcome: Dict[str, Any]
        v_headers_any: Optional[Dict[str, Any]] = None

        if isinstance(res, tuple) and len(res) == 2:
            outcome = cast(Dict[str, Any], res[0] or {})
            v_headers_any = cast(Optional[Dict[str, Any]], res[1] or {})
        elif isinstance(res, dict):
            outcome = cast(Dict[str, Any], res)
        else:
            # Unknown shape -> no-op
            return None, {}

        hdrs = _normalize_headers(outcome, v_headers_any)
        status = hdrs.get("X-Guardrail-Outcome", "error").lower()

        if mode == "enforce":
            override = _map_to_action(status, direction=direction)
            return override, hdrs

        # headers mode
        return None, hdrs

    except Exception:
        # Any issues -> silent no-op to avoid test/behavior regressions
        return None, {}
