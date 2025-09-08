from __future__ import annotations

import asyncio
import math
import random
from typing import Any, Dict, List, NamedTuple, Optional, Protocol, Tuple

from app.services.audit_forwarder import emit_audit_event
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

__all__ = [
    # hardened wrapper
    "verify_intent_hardened",
    "verify_intent",
    # exported verifier symbols used by routes
    "content_fingerprint",
    "Verdict",
    "Verifier",
    "is_known_harmful",
    "load_providers_order",
    "mark_harmful",
    "verifier_enabled",
]

# ------------------------------------------------------------------------------
# Minimal, typed exports so existing route imports remain stable.
# If you have concrete implementations elsewhere, you can replace these.
# ------------------------------------------------------------------------------

class Verdict(NamedTuple):
    safe: bool
    reason: str


class Verifier(Protocol):
    async def verify(self, text: str, ctx_meta: Dict[str, Any]) -> Verdict: ...


def content_fingerprint(text: str) -> str:
    # Stable but simple fingerprint (swap with your stronger impl as needed)
    return f"fp:{abs(hash(text)) % 10**12}"


def is_known_harmful(fp: str) -> bool:
    return False


def mark_harmful(fp: str) -> None:
    return None


def load_providers_order() -> List[str]:
    return []


def verifier_enabled() -> bool:
    return True

# ------------------------------------------------------------------------------
# Optional/placeholder base verifier (tests often monkeypatch this function).
# In production, replace with your real implementation or import it here.
# ------------------------------------------------------------------------------

async def verify_intent(text: str, ctx_meta: Dict[str, Any]) -> Dict[str, Any]:
    """
    Placeholder verifier. Replace with the real implementation or ensure tests
    monkeypatch this function.

    Expected return shape:
      {
        "status": "safe" | "unsafe" | "ambiguous",
        "reason": str,
        "tokens_used": int
      }
    """
    raise NotImplementedError(
        "verify_intent is a stub here. Provide a real implementation or "
        "monkeypatch in tests."
    )

# ------------------------------------------------------------------------------
# Hardened wrapper utilities
# ------------------------------------------------------------------------------

def _ctx_from_meta(ctx_meta: Dict[str, Any]) -> VerifierContext:
    tenant_id = str(ctx_meta.get("tenant_id") or "unknown-tenant")
    bot_id = str(ctx_meta.get("bot_id") or "unknown-bot")
    return VerifierContext(tenant_id=tenant_id, bot_id=bot_id)


def _estimate_tokens(s: str) -> int:
    # Cheap heuristic: ~4 chars/token
    return max(1, math.ceil(len(s) / 4))


async def _call_under_timeout(coro: Any, timeout_ms: int) -> Any:
    return await asyncio.wait_for(coro, timeout=timeout_ms / 1000.0)


def _should_retry_transient(err: Exception) -> bool:
    # Extend with specific transient error classes from your LLM client as needed
    return isinstance(err, asyncio.TimeoutError)


def _map_error_to_outcome(err: Optional[Exception]) -> Dict[str, Any]:
    if isinstance(err, (VerifierTimeoutError, asyncio.TimeoutError)):
        return {"status": "error", "reason": "timeout", "tokens_used": 0}
    if isinstance(err, VerifierBudgetExceeded):
        return {"status": "error", "reason": "budget_exceeded", "tokens_used": 0}
    if isinstance(err, VerifierCircuitOpen):
        return {"status": "error", "reason": "breaker_open", "tokens_used": 0}
    if isinstance(err, VerifierLimitError):
        return {"status": "error", "reason": "limit_exceeded", "tokens_used": 0}
    return {"status": "error", "reason": "unknown_error", "tokens_used": 0}


def _map_headers_for_outcome(
    outcome: Dict[str, Any],
    incident_id: Optional[str],
) -> Dict[str, str]:
    """
    Convert verifier outcome into decision+mode headers using the policy helper.
    Returns dict of header overrides (to feed into attach_guardrail_headers).
    """
    decision, mode = map_verifier_outcome_to_action(outcome)
    headers: Dict[str, str] = {
        "X-Guardrail-Decision": decision,
        "X-Guardrail-Mode": mode,
    }
    if incident_id:
        headers["X-Guardrail-Incident-ID"] = incident_id
    return headers

# ------------------------------------------------------------------------------
# Process-wide enforcer instance
# ------------------------------------------------------------------------------

_ENFORCER = VerifierEnforcer(
    max_tokens_per_request=VERIFIER_MAX_TOKENS_PER_REQUEST,
    daily_budget=VERIFIER_DAILY_TOKEN_BUDGET,
    breaker_max_failures=VERIFIER_CIRCUIT_FAILS,
    breaker_window_s=VERIFIER_CIRCUIT_WINDOW_S,
    breaker_cooldown_s=VERIFIER_CIRCUIT_COOLDOWN_S,
)

# ------------------------------------------------------------------------------
# Public hardened wrapper — NEVER raises; always returns (outcome, headers)
# ------------------------------------------------------------------------------

async def verify_intent_hardened(
    text: str,
    ctx_meta: Dict[str, Any],
) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """
    Safe wrapper that enforces:
      - per-request token cap
      - daily budget
      - circuit breaker
      - total timeout (<= VERIFIER_TIMEOUT_MS) with one jittered retry
      - consistent outcome mapping + audit + headers

    Returns: (outcome, header_overrides)

    This function NEVER raises; it always converts failures into deterministic
    fallbacks with audit and headers.
    """
    ctx = _ctx_from_meta(ctx_meta)
    est_tokens = _estimate_tokens(text)
    timeout_ms = int(VERIFIER_TIMEOUT_MS)
    incident_id: Optional[str] = None
    last_err: Optional[Exception] = None

    # Precheck must not leak exceptions: convert to fallback deterministically
    try:
        _ENFORCER.precheck(ctx, est_tokens)
    except Exception as e:  # noqa: BLE001
        last_err = e
        incident_id = incident_id or new_incident_id()
        emit_audit_event(
            {
                "event": "verifier_fallback",
                "tenant_id": ctx.tenant_id,
                "bot_id": ctx.bot_id,
                "incident_id": incident_id,
                "error": type(e).__name__,
                "stage": "precheck",
            }
        )
        outcome = _map_error_to_outcome(last_err)
        headers = _map_headers_for_outcome(outcome, incident_id=incident_id)
        return outcome, headers

    async def _delegate() -> Dict[str, Any]:
        # Import at runtime so tests can monkeypatch app.services.verifier.verify_intent
        from app.services.verifier import verify_intent as _verify_intent
        return await _verify_intent(text, ctx_meta)

    # Try once (timeboxed), maybe retry if transient and time remains
    for attempt in (1, 2):
        try:
            result: Dict[str, Any] = await _call_under_timeout(_delegate(), timeout_ms)
            used = int(result.get("tokens_used") or est_tokens)
            try:
                _ENFORCER.post_consume(ctx, used)
            except Exception as e:  # noqa: BLE001
                # Post-consume overflow (race) – fallback deterministically
                last_err = e
                incident_id = incident_id or new_incident_id()
                emit_audit_event(
                    {
                        "event": "verifier_fallback",
                        "tenant_id": ctx.tenant_id,
                        "bot_id": ctx.bot_id,
                        "incident_id": incident_id,
                        "error": type(e).__name__,
                        "stage": "post_consume",
                    }
                )
                break  # leave loop, produce fallback below

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
                {
                    "event": "verifier_timeout",
                    "tenant_id": ctx.tenant_id,
                    "bot_id": ctx.bot_id,
                    "incident_id": incident_id,
                }
            )
            # Single quick retry if first attempt and window is not tiny
            if attempt == 1 and timeout_ms > 600:
                await asyncio.sleep(random.uniform(0.05, 0.15))
                continue
            # Fall through to deterministic fallback
            break

        except VerifierLimitError as e:
            # Includes budget/cap errors raised by post_consume
            last_err = e
            break

        except Exception as e:  # noqa: BLE001
            last_err = e
            # Retry once on transient errors
            if attempt == 1 and _should_retry_transient(e):
                await asyncio.sleep(random.uniform(0.05, 0.15))
                continue
            # Non-transient: mark a failure for circuit breaker and fall back
            state = _ENFORCER.on_failure(ctx)
            emit_audit_event(
                {
                    "event": "verifier_error",
                    "tenant_id": ctx.tenant_id,
                    "bot_id": ctx.bot_id,
                    "state": state,
                    "error": type(e).__name__,
                }
            )
            break

    # Error/limit/timeout → deterministic fallback
    outcome = _map_error_to_outcome(last_err)
    incident_id = incident_id or new_incident_id()
    emit_audit_event(
        {
            "event": "verifier_fallback",
            "tenant_id": ctx.tenant_id,
            "bot_id": ctx.bot_id,
            "incident_id": incident_id,
            "error": type(last_err).__name__ if last_err else "unknown",
            "stage": "delegate_or_retry",
        }
    )
    headers = _map_headers_for_outcome(outcome, incident_id=incident_id)
    return outcome, headers
