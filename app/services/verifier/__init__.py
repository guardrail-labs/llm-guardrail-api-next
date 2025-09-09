from __future__ import annotations

import asyncio
import math
import os
import random
import time
from enum import Enum
from threading import RLock
from typing import Any, Dict, List, Optional, Protocol, Set, Tuple

from app.services.audit_forwarder import emit_audit_event
from app.services.policy import current_rules_version, map_verifier_outcome_to_action
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
    VERIFIER_HARM_CACHE_URL,
    VERIFIER_HARM_TTL_DAYS,
    VERIFIER_PROVIDERS,
    VERIFIER_PROVIDER_TIMEOUT_MS,
    VERIFIER_PROVIDER_BREAKER_FAILS,
    VERIFIER_PROVIDER_BREAKER_WINDOW_S,
    VERIFIER_PROVIDER_BREAKER_COOLDOWN_S,
)
from app.services.verifier.providers.base import Provider
from app.services.verifier.provider_breaker import ProviderBreakerRegistry
from app.services.verifier.result_cache import (
    ENABLED as RC_ENABLED,
    CACHE as RC,
    cache_key,
    reset_memory as RC_RESET_MEMORY,
)
from app.telemetry.metrics import (
    inc_verifier_outcome,
    observe_verifier_latency,
    inc_verifier_provider_error,
    inc_verifier_breaker_open,
    inc_verifier_cache_hit,
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

# Clear in-process result cache on module (re)load for test isolation.
# Redis entries (if any) are not cleared.
if os.getenv("VERIFIER_RESULT_CACHE_RESET_ON_IMPORT", "1").strip() == "1":
    try:
        RC_RESET_MEMORY()
    except Exception:
        pass


# ------------------------------------------------------------------------------
# Minimal typed exports used by routes
# ------------------------------------------------------------------------------

class Verdict(Enum):
    SAFE = "safe"
    UNSAFE = "unsafe"
    UNCLEAR = "unclear"


# Per-provider circuit breakers (process-local)
_BREAKERS = ProviderBreakerRegistry(
    VERIFIER_PROVIDER_BREAKER_FAILS,
    VERIFIER_PROVIDER_BREAKER_WINDOW_S,
    VERIFIER_PROVIDER_BREAKER_COOLDOWN_S,
)


# Provider-backed verifier with ordered failover
class Verifier:
    """
    Returns (Optional[Verdict], Optional[str]) where None indicates no provider
    could be reached/constructed.
    """

    def __init__(self, providers: Optional[List[str]] = None) -> None:
        self._provider_names = providers or []
        self._timeout_ms = int(VERIFIER_PROVIDER_TIMEOUT_MS)
        self._providers: List[Provider] = self._build_providers(self._provider_names)

    @staticmethod
    def _build_providers(names: List[str]) -> List[Provider]:
        from app.services.verifier.providers import build_provider

        out: List[Provider] = []
        for n in names:
            p = build_provider(n)
            if p is not None:
                out.append(p)
        return out

    async def _call_with_timebox(
        self,
        prov: Provider,
        text: str,
        meta: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        async def _run() -> Dict[str, Any]:
            return await prov.assess(text, meta=meta)

        return await asyncio.wait_for(_run(), timeout=self._timeout_ms / 1000.0)

    @staticmethod
    def _map_status_to_verdict(status: str) -> Verdict:
        s = (status or "").lower()
        if s == "unsafe":
            return Verdict.UNSAFE
        if s == "safe":
            return Verdict.SAFE
        return Verdict.UNCLEAR

    async def assess_intent(
        self,
        text: str,
        meta: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Optional[Verdict], Optional[str]]:
        if not self._providers:
            return None, None

        last_provider: Optional[str] = None

        for prov in self._providers:
            last_provider = getattr(prov, "name", None) or "unknown"

            # Skip if breaker is open
            if _BREAKERS.is_open(last_provider):
                continue

            try:
                t0 = time.perf_counter()
                result = await self._call_with_timebox(prov, text, meta)
                # Success -> record latency and close breaker
                try:
                    observe_verifier_latency(last_provider, time.perf_counter() - t0)
                except Exception:  # pragma: no cover
                    pass
                _BREAKERS.on_success(last_provider)
            except asyncio.CancelledError:
                # Propagate cancellation promptly (do not swallow).
                raise
            except asyncio.TimeoutError:
                inc_verifier_provider_error(last_provider, "timeout")
                if _BREAKERS.on_failure(last_provider):
                    inc_verifier_breaker_open(last_provider)
                continue
            except Exception:
                inc_verifier_provider_error(last_provider, "error")
                if _BREAKERS.on_failure(last_provider):
                    inc_verifier_breaker_open(last_provider)
                continue

            status = str(result.get("status") or "ambiguous")
            verdict = self._map_status_to_verdict(status)
            if verdict != Verdict.UNCLEAR:
                return verdict, last_provider

        # All providers either failed or were ambiguous
        return Verdict.UNCLEAR, last_provider


# ------------------------------------------------------------------------------
# Fingerprint + harmful cache (hybrid)
# ------------------------------------------------------------------------------

def content_fingerprint(text: str) -> str:
    return f"fp:{abs(hash(text)) % 10**12}"


_HARM_CACHE: Set[str] = set()
_HARM_LOCK = RLock()


def _harm_key(fp: str) -> str:
    return str(fp)


class HarmStore(Protocol):
    def is_known(self, fp: str) -> bool: ...
    def mark(self, fp: str) -> None: ...


class _MemoryHarmStore:
    def is_known(self, fp: str) -> bool:
        k = _harm_key(fp)
        with _HARM_LOCK:
            return k in _HARM_CACHE

    def mark(self, fp: str) -> None:
        k = _harm_key(fp)
        with _HARM_LOCK:
            _HARM_CACHE.add(k)


class _RedisHarmStore:
    def __init__(self, url: str, ttl_seconds: int) -> None:
        self._ttl = int(max(1, ttl_seconds))
        self._cli = None
        try:
            import redis  # type: ignore
            self._cli = redis.from_url(url, decode_responses=True)
        except Exception:
            self._cli = None

    @staticmethod
    def _key(fp: str) -> str:
        return f"harm:fp:{fp}"

    def is_known(self, fp: str) -> bool:
        if not self._cli:
            return False
        try:
            return bool(self._cli.exists(self._key(fp)))
        except Exception:
            return False

    def mark(self, fp: str) -> None:
        if not self._cli:
            return
        try:
            self._cli.setex(self._key(fp), self._ttl, "1")
        except Exception:
            return


def _build_harm_store() -> HarmStore:
    url = (VERIFIER_HARM_CACHE_URL or "").strip()
    ttl_days = int(max(1, int(VERIFIER_HARM_TTL_DAYS or 90)))
    ttl_seconds = ttl_days * 24 * 60 * 60
    if url:
        store = _RedisHarmStore(url, ttl_seconds)
        mem = _MemoryHarmStore()

        class _Hybrid:
            def is_known(self, fp: str) -> bool:
                if mem.is_known(fp):
                    return True
                if store.is_known(fp):
                    mem.mark(fp)
                    return True
                return False

            def mark(self, fp: str) -> None:
                mem.mark(fp)
                store.mark(fp)

        return _Hybrid()
    return _MemoryHarmStore()


_HARM_STORE: HarmStore = _build_harm_store()


def is_known_harmful(fp: str) -> bool:
    return bool(_HARM_STORE.is_known(fp))


def mark_harmful(fp: str) -> None:
    _HARM_STORE.mark(fp)


def load_providers_order() -> List[str]:
    """
    Return provider order, honoring dynamic env overrides.
    Env var takes precedence; falls back to compiled setting.
    """
    raw = os.getenv("VERIFIER_PROVIDERS", VERIFIER_PROVIDERS) or "local_rules"
    return [p.strip() for p in raw.split(",") if p.strip()]


def verifier_enabled() -> bool:
    return True


# ------------------------------------------------------------------------------
# Provider-backed verify_intent with cache, breaker, metrics surfacing
# ------------------------------------------------------------------------------

async def verify_intent(text: str, ctx_meta: Dict[str, Any]) -> Dict[str, Any]:
    """
    Provider-backed verification. Returns legacy shape plus "provider":
      {"status": "...", "reason": "...", "tokens_used": N, "provider": "name"}
    """
    from app.services.verifier.providers import build_provider  # lazy import

    # Cache lookup (zero-token)
    tenant = str(ctx_meta.get("tenant_id") or "unknown-tenant")
    bot = str(ctx_meta.get("bot_id") or "unknown-bot")
    policy_ver = current_rules_version()
    fp = content_fingerprint(text)
    ck = cache_key(tenant, bot, fp, policy_ver)

    if RC_ENABLED:
        hit = RC.get(ck)
        if hit in ("safe", "unsafe"):
            try:
                inc_verifier_cache_hit(hit)
                inc_verifier_outcome("cache", hit)
            except Exception:
                pass
            if hit == "unsafe":
                try:
                    mark_harmful(fp)
                except Exception:
                    pass
            return {
                "status": hit,
                "reason": "cached",
                "tokens_used": 0,
                "provider": "cache",
            }

    provider_names = load_providers_order()
    est_tokens = max(1, len(text) // 4)
    timeout_s = max(0.05, float(VERIFIER_PROVIDER_TIMEOUT_MS) / 1000.0)

    last_provider: Optional[str] = None

    for name in provider_names:
        prov = build_provider(name)
        if prov is None:
            continue
        last_provider = getattr(prov, "name", None) or name or "unknown"

        # Skip if breaker is open
        if _BREAKERS.is_open(last_provider):
            continue

        try:
            async def _run() -> Dict[str, Any]:
                return await prov.assess(text, meta=ctx_meta)

            t0 = time.perf_counter()
            res: Dict[str, Any] = await asyncio.wait_for(_run(), timeout=timeout_s)

            # Guard telemetry so failures never affect pipeline behavior.
            try:
                observe_verifier_latency(str(last_provider), time.perf_counter() - t0)
            except Exception:  # pragma: no cover
                pass

            _BREAKERS.on_success(str(last_provider))

        except asyncio.CancelledError:
            # Propagate cancellation promptly.
            raise
        except asyncio.TimeoutError:
            try:
                inc_verifier_provider_error(str(last_provider), "timeout")
            except Exception:
                pass
            if _BREAKERS.on_failure(str(last_provider)):
                try:
                    inc_verifier_breaker_open(str(last_provider))
                except Exception:
                    pass
            continue
        except Exception:
            try:
                inc_verifier_provider_error(str(last_provider), "error")
            except Exception:
                pass
            if _BREAKERS.on_failure(str(last_provider)):
                try:
                    inc_verifier_breaker_open(str(last_provider))
                except Exception:
                    pass
            continue

        status = str(res.get("status") or "ambiguous").lower()
        reason = str(res.get("reason") or "")
        tokens_used = int(res.get("tokens_used") or est_tokens)

        try:
            inc_verifier_outcome(str(last_provider), status)
        except Exception:
            pass

        if status in ("safe", "unsafe"):
            # Store decisive outcomes only
            if RC_ENABLED:
                try:
                    RC.set(ck, status)
                except Exception:
                    pass
            if status == "unsafe":
                try:
                    mark_harmful(fp)
                except Exception:
                    pass
            return {
                "status": status,
                "reason": reason,
                "tokens_used": tokens_used,
                "provider": str(last_provider),
            }

    if last_provider:
        try:
            inc_verifier_outcome(str(last_provider), "ambiguous")
        except Exception:
            pass

    return {
        "status": "ambiguous",
        "reason": "",
        "tokens_used": est_tokens,
        "provider": str(last_provider or "unknown"),
    }


# ------------------------------------------------------------------------------
# Hardened wrapper (provider surfaced in headers/audit)
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
    prov = outcome.get("provider")
    if isinstance(prov, str) and prov:
        headers["X-Guardrail-Verifier"] = prov
    return headers


_ENFORCER = VerifierEnforcer(
    max_tokens_per_request=VERIFIER_MAX_TOKENS_PER_REQUEST,
    daily_budget=VERIFIER_DAILY_TOKEN_BUDGET,
    breaker_max_failures=VERIFIER_CIRCUIT_FAILS,
    breaker_window_s=VERIFIER_CIRCUIT_WINDOW_S,
    breaker_cooldown_s=VERIFIER_CIRCUIT_COOLDOWN_S,
)


async def verify_intent_hardened(
    text: str,
    ctx_meta: Dict[str, Any],
) -> Tuple[Dict[str, Any], Dict[str, str]]:
    ctx = _ctx_from_meta(ctx_meta)
    est_tokens = _estimate_tokens(text)
    timeout_ms = int(VERIFIER_TIMEOUT_MS)
    incident_id: Optional[str] = None
    last_err: Optional[Exception] = None

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
                "verifier_provider": None,
            }
        )
        outcome = _map_error_to_outcome(last_err)
        headers = _map_headers_for_outcome(outcome, incident_id=incident_id)
        return outcome, headers

    async def _delegate() -> Dict[str, Any]:
        from app.services.verifier import verify_intent as _verify_intent

        return await _verify_intent(text, ctx_meta)

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
                        "verifier_provider": result.get("provider"),
                    }
                )
                break

            _ENFORCER.on_success(ctx)

            outcome = {
                "status": str(result.get("status") or "ambiguous"),
                "reason": str(result.get("reason") or ""),
                "tokens_used": used,
            }
            prov = result.get("provider")
            if isinstance(prov, str) and prov:
                outcome["provider"] = prov

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
                    "verifier_provider": None,
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
                    "verifier_provider": None,
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
            "verifier_provider": None,
        }
    )
    headers = _map_headers_for_outcome(outcome, incident_id=incident_id)
    return outcome, headers
