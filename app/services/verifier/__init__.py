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
from app.services.policy import current_rules_version, map_verifier_outcome_to_headers
from app.services.verifier.config import get_verifier_latency_budget_ms
from app.services.verifier.provider_breaker import ProviderBreakerRegistry
from app.services.verifier.provider_quota import QuotaSkipRegistry
from app.services.verifier.provider_router import ProviderRouter
from app.services.verifier.providers.base import Provider, ProviderRateLimited
from app.services.verifier.result_cache import (
    CACHE as RC,
    ENABLED as RC_ENABLED,
    cache_key,
    reset_memory as RC_RESET_MEMORY,
)
from app.services.verifier.sandbox import analyze_and_surface_diffs, maybe_schedule_sandbox
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
    VERIFIER_PROVIDER_BREAKER_COOLDOWN_S,
    VERIFIER_PROVIDER_BREAKER_FAILS,
    VERIFIER_PROVIDER_BREAKER_WINDOW_S,
    VERIFIER_PROVIDER_QUOTA_SKIP_ENABLED,
    VERIFIER_PROVIDER_TIMEOUT_MS,
    VERIFIER_PROVIDERS,
    VERIFIER_TIMEOUT_MS,
)
from app.telemetry.metrics import (
    inc_route_rank,
    inc_route_reorder,
    inc_verifier_breaker_open,
    inc_verifier_cache_hit,
    inc_verifier_outcome,
    inc_verifier_provider_error,
    inc_verifier_quota,
    observe_verifier_latency,
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
    "get_ops_overview",
]

# Clear in-process result cache on module (re)load for test isolation.
if os.getenv("VERIFIER_RESULT_CACHE_RESET_ON_IMPORT", "1").strip() == "1":
    try:
        RC_RESET_MEMORY()
    except Exception:
        pass


class Verdict(Enum):
    SAFE = "safe"
    UNSAFE = "unsafe"
    UNCLEAR = "unclear"


_BREAKERS = ProviderBreakerRegistry(
    VERIFIER_PROVIDER_BREAKER_FAILS,
    VERIFIER_PROVIDER_BREAKER_WINDOW_S,
    VERIFIER_PROVIDER_BREAKER_COOLDOWN_S,
)

_QUOTA = QuotaSkipRegistry()
_ROUTER = ProviderRouter()


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
            pname = getattr(prov, "name", None) or "unknown"

            # Breaker check BEFORE adopting as last_provider
            if _BREAKERS.is_open(pname):
                continue

            # Quota-aware skip (if enabled)
            if VERIFIER_PROVIDER_QUOTA_SKIP_ENABLED and _QUOTA.is_skipped(pname):
                try:
                    inc_verifier_quota(pname, "skipped")
                except Exception:
                    pass
                continue

            # Only assign last_provider once we intend to try it
            last_provider = pname

            try:
                t0 = time.perf_counter()
                result = await self._call_with_timebox(prov, text, meta)
                try:
                    observe_verifier_latency(pname, time.perf_counter() - t0)
                except Exception:  # pragma: no cover - metrics must not affect control flow
                    pass
                _BREAKERS.on_success(pname)
                try:
                    _QUOTA.clear(pname)
                    inc_verifier_quota(pname, "reset")
                except Exception:
                    pass
            except asyncio.CancelledError:
                raise
            except asyncio.TimeoutError:
                inc_verifier_provider_error(pname, "timeout")
                if _BREAKERS.on_failure(pname):
                    inc_verifier_breaker_open(pname)
                continue
            except ProviderRateLimited as e:
                try:
                    _ = _QUOTA.on_rate_limited(pname, getattr(e, "retry_after_s", None))
                    inc_verifier_quota(pname, "rate_limited")
                except Exception:
                    pass
                # Do not trip breaker on quota; skip to next
                continue
            except Exception:
                inc_verifier_provider_error(pname, "error")
                if _BREAKERS.on_failure(pname):
                    inc_verifier_breaker_open(pname)
                continue

            status = str(result.get("status") or "ambiguous")
            verdict = self._map_status_to_verdict(status)
            if verdict != Verdict.UNCLEAR:
                # Fire sandbox for alternates; do not block unless tests demand it
                try:
                    _ = await maybe_schedule_sandbox(
                        primary=pname,
                        all_providers=self._provider_names,
                        text=text,
                        meta=meta or {},
                    )
                except Exception:
                    pass
                return verdict, last_provider

        return Verdict.UNCLEAR, last_provider


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
            import redis

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


def get_ops_overview(tenant: str | None = None, bot: str | None = None) -> Dict[str, object]:
    """Return a snapshot of verifier ops state."""
    provs = load_providers_order()

    # Current effective order for the requested tenant/bot (or default).
    # IMPORTANT: do NOT call _ROUTER.rank() here, it mutates sticky timestamps.
    t = tenant or "default"
    b = bot or "default"
    effective_order = list(provs)
    try:
        last_orders = _ROUTER.get_last_order_snapshot()
        for entry in last_orders:
            if entry.get("tenant") == t and entry.get("bot") == b:
                cached = entry.get("order")
                if isinstance(cached, list) and cached:
                    effective_order = list(cached)
                break
    except Exception:
        pass

    return {"providers": provs, "effective_order": effective_order}


async def verify_intent(text: str, ctx_meta: Dict[str, Any]) -> Dict[str, Any]:
    """
    Provider-backed verification. Returns legacy shape plus "provider":
      {"status": "...", "reason": "...", "tokens_used": N, "provider": "name"}
    """
    from app.services.verifier.providers import build_provider  # lazy import

    tenant = str(ctx_meta.get("tenant_id") or "unknown-tenant")
    bot = str(ctx_meta.get("bot_id") or "unknown-bot")
    policy_ver = current_rules_version()
    fp = content_fingerprint(text)
    ck = cache_key(tenant, bot, fp, policy_ver)

    # Cache lookup (zero-token)
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

    # Provider ordering (adaptive)
    base_names = load_providers_order()
    ordered = _ROUTER.rank(tenant, bot, base_names)
    for idx, name in enumerate(ordered, start=1):
        try:
            inc_route_rank(tenant, bot, name, idx)
        except Exception:
            pass
    if ordered and base_names and ordered[0] != base_names[0]:
        try:
            inc_route_reorder(tenant, bot, base_names[0], ordered[0])
        except Exception:
            pass

    provider_names = ordered
    est_tokens = max(1, len(text) // 4)
    timeout_s = max(0.05, float(VERIFIER_PROVIDER_TIMEOUT_MS) / 1000.0)
    budget_ms = get_verifier_latency_budget_ms()
    budget_s = (budget_ms / 1000.0) if budget_ms is not None else None

    last_provider: Optional[str] = None

    for name in provider_names:
        prov = build_provider(name)
        if prov is None:
            continue

        pname = getattr(prov, "name", None) or name or "unknown"

        # Breaker check BEFORE adopting as last_provider
        if _BREAKERS.is_open(pname):
            continue

        # Quota-aware skip (if enabled)
        if VERIFIER_PROVIDER_QUOTA_SKIP_ENABLED and _QUOTA.is_skipped(pname):
            try:
                inc_verifier_quota(pname, "skipped")
            except Exception:
                pass
            continue

        # Only now adopt as last_provider since we intend to try it
        last_provider = pname

        try:

            async def _run() -> Dict[str, Any]:
                return await prov.assess(text, meta=ctx_meta)

            t0 = time.perf_counter()
            eff_timeout = min(timeout_s, budget_s) if budget_s is not None else timeout_s
            res: Dict[str, Any] = await asyncio.wait_for(_run(), timeout=eff_timeout)

            try:
                observe_verifier_latency(pname, time.perf_counter() - t0)
            except Exception:  # pragma: no cover - metrics must not affect control flow
                pass

            _BREAKERS.on_success(pname)
            try:
                _QUOTA.clear(pname)
                inc_verifier_quota(pname, "reset")
            except Exception:
                pass

        except asyncio.CancelledError:
            raise
        except asyncio.TimeoutError:
            try:
                inc_verifier_provider_error(pname, "timeout")
            except Exception:
                pass
            if _BREAKERS.on_failure(pname):
                try:
                    inc_verifier_breaker_open(pname)
                except Exception:
                    pass
            try:
                _ROUTER.record_timeout(tenant, bot, pname)
            except Exception:
                pass
            return {
                "status": "timeout",
                "reason": "latency_budget_exceeded",
                "tokens_used": est_tokens,
                "provider": pname,
            }
        except ProviderRateLimited as e:
            try:
                _ = _QUOTA.on_rate_limited(pname, getattr(e, "retry_after_s", None))
                inc_verifier_quota(pname, "rate_limited")
            except Exception:
                pass
            try:
                _ROUTER.record_rate_limited(tenant, bot, pname)
            except Exception:
                pass
            continue
        except Exception:
            try:
                inc_verifier_provider_error(pname, "error")
            except Exception:
                pass
            if _BREAKERS.on_failure(pname):
                try:
                    inc_verifier_breaker_open(pname)
                except Exception:
                    pass
            try:
                _ROUTER.record_error(tenant, bot, pname)
            except Exception:
                pass
            continue

        status = str(res.get("status") or "ambiguous").lower()
        reason = str(res.get("reason") or "")
        tokens_used = int(res.get("tokens_used") or est_tokens)

        try:
            inc_verifier_outcome(pname, status)
        except Exception:
            pass

        if status in ("safe", "unsafe"):
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
            # success feedback to router
            try:
                _ROUTER.record_success(tenant, bot, pname, time.perf_counter() - t0)
            except Exception:
                pass

            out: Dict[str, Any] = {
                "status": status,
                "reason": reason,
                "tokens_used": tokens_used,
                "provider": pname,
            }

            # Launch sandbox and analyze disagreements (non-blocking in prod; sync in tests)
            try:
                sb = await maybe_schedule_sandbox(
                    primary=pname,
                    all_providers=provider_names,
                    text=text,
                    meta=ctx_meta,
                )
                if sb is not None:
                    tenant_id = tenant
                    bot_id = bot
                    summary = analyze_and_surface_diffs(pname, status, sb, tenant_id, bot_id)
                    if summary:
                        res_extra = out if isinstance(out, dict) else {}
                        res_extra["sandbox_summary"] = summary
                        out = res_extra
            except Exception:
                pass

            return out

        # ambiguous: treat as non-decisive; continue loop

    if last_provider:
        try:
            inc_verifier_outcome(last_provider, "ambiguous")
        except Exception:
            pass

    return {
        "status": "ambiguous",
        "reason": "",
        "tokens_used": est_tokens,
        "provider": str(last_provider or "unknown"),
    }


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
    decision, mode = map_verifier_outcome_to_headers(outcome)
    headers: Dict[str, str] = {
        "X-Guardrail-Decision": decision,
        "X-Guardrail-Mode": mode,
    }
    if incident_id:
        headers["X-Guardrail-Incident-ID"] = incident_id
    prov = outcome.get("provider")
    if isinstance(prov, str) and prov:
        headers["X-Guardrail-Verifier"] = prov
    summ = outcome.get("sandbox_summary")
    if isinstance(summ, str) and summ:
        headers["X-Guardrail-Sandbox"] = summ
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
