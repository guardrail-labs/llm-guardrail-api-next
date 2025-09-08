from __future__ import annotations

import asyncio
import hashlib
import math
import os
import random
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

if "emit_audit_event" not in globals():  # allow monkeypatched emit_audit_event to persist across reloads
    from app.services.audit_forwarder import emit_audit_event as _emit_audit_event

    def emit_audit_event(event_type: str, payload: Dict[str, Any]) -> None:
        _emit_audit_event({"type": event_type, **payload})

from app.services.policy import map_verifier_outcome_to_action
from app.services.verifier_limits import (
    VerifierBudgetExceeded,
    VerifierCircuitOpen,
    VerifierContext,
    VerifierEnforcer,
    VerifierLimitError,
    VerifierTimeoutError,
    new_incident_id,
)
from app.settings import (
    VERIFIER_CIRCUIT_COOLDOWN_S,
    VERIFIER_CIRCUIT_FAILS,
    VERIFIER_CIRCUIT_WINDOW_S,
    VERIFIER_DAILY_TOKEN_BUDGET,
    VERIFIER_MAX_TOKENS_PER_REQUEST,
    VERIFIER_TIMEOUT_MS,
)


class Verdict(str, Enum):
    SAFE = "safe"
    UNSAFE = "unsafe"
    UNCLEAR = "unclear"


def content_fingerprint(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


# --- simple in-memory cache (can be replaced later) ---
_known_harmful: Dict[str, bool] = {}  # fp -> True


def mark_harmful(fp: str) -> None:
    _known_harmful[fp] = True


def is_known_harmful(fp: str) -> bool:
    return _known_harmful.get(fp, False)


# --- provider adapters (non-executing, classification-only) ---
ProviderFn = Callable[[str, Dict[str, Any]], Verdict]


def provider_gemini(text: str, meta: Dict[str, Any]) -> Verdict:
    hint = meta.get("hint") or ""
    if "force_unsafe" in hint:
        return Verdict.UNSAFE
    if "force_unclear" in hint:
        return Verdict.UNCLEAR
    return Verdict.SAFE


def provider_claude(text: str, meta: Dict[str, Any]) -> Verdict:
    hint = meta.get("hint") or ""
    if "force_unsafe" in hint:
        return Verdict.UNSAFE
    if "force_unclear" in hint:
        return Verdict.UNCLEAR
    return Verdict.SAFE


PROVIDERS: Dict[str, ProviderFn] = {
    "gemini": provider_gemini,
    "claude": provider_claude,
}


class Verifier:
    def __init__(self, providers_order: List[str]) -> None:
        self.providers_order = providers_order

    def assess_intent(
        self, text: str, meta: Optional[Dict[str, Any]] = None
    ) -> Tuple[Verdict, Optional[str]]:
        meta = meta or {}
        for name in self.providers_order:
            fn = PROVIDERS.get(name)
            if not fn:
                continue
            try:
                verdict = fn(text, meta)
                return verdict, name
            except Exception:
                continue
        return None, None  # type: ignore


def load_providers_order() -> List[str]:
    s = os.getenv("VERIFIER_PROVIDERS", "gemini,claude")
    return [p.strip() for p in s.split(",") if p.strip()]


def verifier_enabled() -> bool:
    return os.getenv("VERIFIER_ENABLED", "false").lower() == "true"


# ---- Hardened verifier wrapper -----------------------------------------------

_ENFORCER = VerifierEnforcer(
    max_tokens_per_request=VERIFIER_MAX_TOKENS_PER_REQUEST,
    daily_budget=VERIFIER_DAILY_TOKEN_BUDGET,
    breaker_max_failures=VERIFIER_CIRCUIT_FAILS,
    breaker_window_s=VERIFIER_CIRCUIT_WINDOW_S,
    breaker_cooldown_s=VERIFIER_CIRCUIT_COOLDOWN_S,
)


def _ctx_from_meta(ctx_meta: Dict[str, Any]) -> VerifierContext:
    tenant_id = str(ctx_meta.get("tenant_id") or "unknown-tenant")
    bot_id = str(ctx_meta.get("bot_id") or "unknown-bot")
    return VerifierContext(tenant_id=tenant_id, bot_id=bot_id)


def _estimate_tokens(s: str) -> int:
    # Cheap heuristic: ~4 chars/token
    return max(1, math.ceil(len(s) / 4))


async def _call_under_timeout(coro, timeout_ms: int):
    return await asyncio.wait_for(coro, timeout=timeout_ms / 1000.0)


def _should_retry_transient(err: Exception) -> bool:
    # Extend with specific transient error classes from your LLM client
    return isinstance(err, (asyncio.TimeoutError,))


if "verify_intent" not in globals():
    async def verify_intent(text: str, ctx_meta: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback verifier implementation used in tests."""
        await asyncio.sleep(0)
        return {
            "status": "safe",
            "reason": "",
            "tokens_used": _estimate_tokens(text),
        }


async def verify_intent_hardened(
    text: str, ctx_meta: Dict[str, Any]
) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """
    Safe wrapper that enforces:
      - per-request token cap
      - daily budget
      - circuit breaker
      - total timeout (with at most one jittered retry)
      - consistent outcome mapping + audit + headers
    Returns: (outcome, header_overrides)
    """
    ctx = _ctx_from_meta(ctx_meta)
    est_tokens = _estimate_tokens(text)
    _ENFORCER.precheck(ctx, est_tokens)

    timeout_ms = int(VERIFIER_TIMEOUT_MS)
    incident_id: Optional[str] = None
    last_err: Optional[Exception] = None

    async def _delegate() -> Dict[str, Any]:
        # Import here to allow monkeypatching without circulars
        from app.services.verifier import verify_intent

        return await verify_intent(text, ctx_meta)

    # Try once (with timebox), maybe retry if transient and still within budget/timebox
    for attempt in (1, 2):
        try:
            result: Dict[str, Any] = await _call_under_timeout(_delegate(), timeout_ms)
            used = int(result.get("tokens_used") or est_tokens)
            _ENFORCER.post_consume(ctx, used)
            _ENFORCER.on_success(ctx)

            outcome = {
                "status": str(result.get("status") or "ambiguous"),
                "reason": str(result.get("reason") or ""),
                "tokens_used": used,
            }
            headers = _map_headers_for_outcome(outcome, incident_id=None)
            return outcome, headers

        except asyncio.TimeoutError as e:
            last_err = e
            incident_id = incident_id or new_incident_id()
            emit_audit_event(
                "verifier_timeout",
                {"tenant_id": ctx.tenant_id, "bot_id": ctx.bot_id, "incident_id": incident_id},
            )
            # No retry after timeout if total window is consumed
            if attempt == 1 and timeout_ms > 600:
                # jittered short backoff before a final quick retry
                await asyncio.sleep(random.uniform(0.05, 0.15))
                continue
            raise VerifierTimeoutError("Verifier timed out") from e
        except VerifierLimitError as e:
            # Budget/cap errors may be raised by post_consume as well
            last_err = e
            break
        except Exception as e:
            last_err = e
            # retry once if transient
            if attempt == 1 and _should_retry_transient(e):
                await asyncio.sleep(random.uniform(0.05, 0.15))
                continue
            # mark a failure for breaker
            state = _ENFORCER.on_failure(ctx)
            emit_audit_event(
                "verifier_error",
                {
                    "tenant_id": ctx.tenant_id,
                    "bot_id": ctx.bot_id,
                    "state": state,
                    "error": type(e).__name__,
                },
            )
            break

    # If we reach here, we had an error/limit/timeout
    outcome = _map_error_to_outcome(last_err)
    incident_id = incident_id or new_incident_id()
    emit_audit_event(
        "verifier_fallback",
        {
            "tenant_id": ctx.tenant_id,
            "bot_id": ctx.bot_id,
            "incident_id": incident_id,
            "error": type(last_err).__name__ if last_err else "unknown",
        },
    )
    headers = _map_headers_for_outcome(outcome, incident_id=incident_id)
    return outcome, headers


def _map_error_to_outcome(err: Optional[Exception]) -> Dict[str, Any]:
    if isinstance(err, VerifierTimeoutError):
        return {"status": "error", "reason": "timeout", "tokens_used": 0}
    if isinstance(err, VerifierBudgetExceeded):
        return {"status": "error", "reason": "budget_exceeded", "tokens_used": 0}
    if isinstance(err, VerifierCircuitOpen):
        return {"status": "error", "reason": "breaker_open", "tokens_used": 0}
    if isinstance(err, VerifierLimitError):
        return {"status": "error", "reason": "limit_exceeded", "tokens_used": 0}
    return {"status": "error", "reason": "unknown_error", "tokens_used": 0}


def _map_headers_for_outcome(outcome: Dict[str, Any], incident_id: Optional[str]) -> Dict[str, str]:
    """
    Convert verifier outcome into decision+mode headers using the policy helper.
    Returns dict of header overrides (to feed into attach_guardrail_headers).
    """
    decision, mode = map_verifier_outcome_to_action(outcome)
    headers = {
        "X-Guardrail-Decision": decision,
        "X-Guardrail-Mode": mode,
    }
    if incident_id:
        headers["X-Guardrail-Incident-ID"] = incident_id
    return headers
