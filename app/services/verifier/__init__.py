from __future__ import annotations

import asyncio
import math
import random
from enum import Enum
from threading import RLock
from typing import Any, Dict, List, Optional, Set, Tuple

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
    VERIFIER_HARM_CACHE_URL,
    VERIFIER_HARM_TTL_DAYS,
    VERIFIER_MAX_TOKENS_PER_REQUEST,
    VERIFIER_TIMEOUT_MS,
)

__all__ = [
    "verify_intent_hardened",
    "verify_intent",
    "content_fingerprint",
    "Verdict",
    "Verifier",
    "is_known_harmful",
    "load_providers_order",
    "mark_harmful",
    "verifier_enabled",
]

# ------------------------------------------------------------------------------
# Minimal typed exports used by routes
# ------------------------------------------------------------------------------


class Verdict(Enum):
    SAFE = "safe"
    UNSAFE = "unsafe"
    UNCLEAR = "unclear"


class Verifier:
    """
    Minimal stub Verifier compatible with routes/batch.py:
      v = Verifier(providers)
      verdict, provider = await v.assess_intent(text, meta={...})
    Replace with a real implementation as needed.
    """

    def __init__(self, providers: Optional[List[str]] = None) -> None:
        self.providers = providers or []

    async def assess_intent(
        self,
        text: str,
        meta: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Optional[Verdict], Optional[str]]:
        # Default stub: undecided → UNCLEAR, no provider resolved.
        return Verdict.UNCLEAR, (self.providers[0] if self.providers else None)


def content_fingerprint(text: str) -> str:
    return f"fp:{abs(hash(text)) % 10**12}"


# ------------------------------------------------------------------------------
# Harmful fingerprint cache (Redis with TTL if available; safe in-memory fallback)
# ------------------------------------------------------------------------------


class _MemoryHarmStore:
    def __init__(self) -> None:
        self._s: Set[str] = set()
        self._lk = RLock()

    def is_known(self, fp: str) -> bool:
        k = str(fp)
        with self._lk:
            return k in self._s

    def mark(self, fp: str) -> None:
        k = str(fp)
        with self._lk:
            self._s.add(k)


class _RedisHarmStore:
    def __init__(self, url: str, ttl_seconds: int) -> None:
        self._ttl = int(max(1, ttl_seconds))
        self._url = url
        self._cli = None
        try:
            # Lazy optional dependency; do not hard-require redis
            import redis

            self._cli = redis.from_url(url, decode_responses=True)
        except Exception:
            self._cli = None  # degrade to memory

    @staticmethod
    def _key(fp: str) -> str:
        return f"harm:fp:{fp}"

    def is_known(self, fp: str) -> bool:
        if not self._cli:
            return False
        try:
            # EXISTS returns int/boolean depending on client; normalize to bool
            return bool(self._cli.exists(self._key(fp)))
        except Exception:
            return False

    def mark(self, fp: str) -> None:
        if not self._cli:
            return
        try:
            # set value with TTL; value is irrelevant
            self._cli.setex(self._key(fp), self._ttl, "1")
        except Exception:
            # On any Redis failure, swallow and let wrapper behave as if unknown
            return


def _build_harm_store() -> Any:
    url = (VERIFIER_HARM_CACHE_URL or "").strip()
    ttl_days = int(max(1, int(VERIFIER_HARM_TTL_DAYS or 90)))
    ttl_seconds = ttl_days * 24 * 60 * 60
    if url:
        store = _RedisHarmStore(url, ttl_seconds)
        # If client couldn't initialize, it returns "unknown" on read and no-op on write.
        # We still keep a memory store in front to preserve deny decisions within a process.
        mem = _MemoryHarmStore()

        class _Hybrid:
            def is_known(self, fp: str) -> bool:
                # Memory hit is fastest; if not, consult Redis.
                if mem.is_known(fp):
                    return True
                if store.is_known(fp):
                    # warm local cache for subsequent requests
                    mem.mark(fp)
                    return True
                return False

            def mark(self, fp: str) -> None:
                mem.mark(fp)
                store.mark(fp)

        return _Hybrid()
    return _MemoryHarmStore()


_HARM_STORE = _build_harm_store()


def is_known_harmful(fp: str) -> bool:
    """Return True if the fingerprint is known harmful."""
    return bool(_HARM_STORE.is_known(fp))


def mark_harmful(fp: str) -> None:
    """Record the fingerprint as harmful for future deny when verifier is down."""
    _HARM_STORE.mark(fp)


def load_providers_order() -> List[str]:
    return []


def verifier_enabled() -> bool:
    return True


# ------------------------------------------------------------------------------
# Optional base verifier (tests typically monkeypatch this)
# ------------------------------------------------------------------------------


async def verify_intent(text: str, ctx_meta: Dict[str, Any]) -> Dict[str, Any]:
    """
    Replace with real implementation or monkeypatch in tests.

    Returns:
      {
        "status": "safe" | "unsafe" | "ambiguous",
        "reason": str,
        "tokens_used": int
      }
    """
    raise NotImplementedError(
        "verify_intent is a stub here; provide a real impl or monkeypatch in tests."
    )


# ------------------------------------------------------------------------------
# Hardened wrapper utilities
# ------------------------------------------------------------------------------


def _ctx_from_meta(ctx_meta: Dict[str, Any]) -> VerifierContext:
    tenant_id = str(ctx_meta.get("tenant_id") or "unknown-tenant")
    bot_id = str(ctx_meta.get("bot_id") or "unknown-bot")
    return VerifierContext(tenant_id=tenant_id, bot_id=bot_id)


def _estimate_tokens(s: str) -> int:
    return max(1, math.ceil(len(s) / 4))


async def _call_under_timeout(coro: Any, timeout_ms: int) -> Any:
    return await asyncio.wait_for(coro, timeout=timeout_ms / 1000.0)


def _should_retry_transient(err: Exception) -> bool:
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
    decision, mode = map_verifier_outcome_to_action(outcome)
    headers: Dict[str, str] = {
        "X-Guardrail-Decision": decision,
        "X-Guardrail-Mode": mode,
    }
    if incident_id:
        headers["X-Guardrail-Incident-ID"] = incident_id
    return headers


# ------------------------------------------------------------------------------
# Process-wide enforcer
# ------------------------------------------------------------------------------


_ENFORCER = VerifierEnforcer(
    max_tokens_per_request=VERIFIER_MAX_TOKENS_PER_REQUEST,
    daily_budget=VERIFIER_DAILY_TOKEN_BUDGET,
    breaker_max_failures=VERIFIER_CIRCUIT_FAILS,
    breaker_window_s=VERIFIER_CIRCUIT_WINDOW_S,
    breaker_cooldown_s=VERIFIER_CIRCUIT_COOLDOWN_S,
)


# ------------------------------------------------------------------------------
# Public hardened wrapper — NEVER raises
# ------------------------------------------------------------------------------


async def verify_intent_hardened(
    text: str,
    ctx_meta: Dict[str, Any],
) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """
    Enforces caps, budgets, breaker, timeout (with one jittered retry),
    and maps outcomes to deterministic fallbacks + headers.
    """
    ctx = _ctx_from_meta(ctx_meta)
    est_tokens = _estimate_tokens(text)
    timeout_ms = int(VERIFIER_TIMEOUT_MS)
    incident_id: Optional[str] = None
    last_err: Optional[Exception] = None

    # Precheck: convert all failures to fallback
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
        # runtime import so tests can monkeypatch this symbol
        from app.services.verifier import verify_intent as _verify_intent

        return await _verify_intent(text, ctx_meta)

    # Try once; optionally retry transiently
    for attempt in (1, 2):
        try:
            result: Dict[str, Any] = await _call_under_timeout(_delegate(), timeout_ms)
            used = int(result.get("tokens_used") or est_tokens)
            try:
                _ENFORCER.post_consume(ctx, used)
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
                        "stage": "post_consume",
                    }
                )
                break

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
            if attempt == 1 and timeout_ms > 600:
                await asyncio.sleep(random.uniform(0.05, 0.15))
                continue
            break

        except VerifierLimitError as e:
            last_err = e
            break

        except Exception as e:  # noqa: BLE001
            last_err = e
            if attempt == 1 and _should_retry_transient(e):
                await asyncio.sleep(random.uniform(0.05, 0.15))
                continue
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

