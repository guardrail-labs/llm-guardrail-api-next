from __future__ import annotations

import asyncio
import random
import random as _rand
import time
from typing import Any, Dict, Iterable, List, Optional

from app.services.audit_forwarder import emit_audit_event
from app.services.verifier.providers import build_provider
from app.settings import (
    VERIFIER_SANDBOX_DIFF_ATTACH_HEADER,
    VERIFIER_SANDBOX_DIFF_AUDIT_RATE,
    VERIFIER_SANDBOX_DIFF_ENABLED,
    VERIFIER_SANDBOX_DIFF_MAX_ATTACH,
    VERIFIER_SANDBOX_DIFF_ONLY_ON_DECISIVE,
    VERIFIER_SANDBOX_ENABLED,
    VERIFIER_SANDBOX_MAX_CONCURRENCY,
    VERIFIER_SANDBOX_MAX_RESULTS,
    VERIFIER_SANDBOX_SAMPLE_RATE,
    VERIFIER_SANDBOX_SYNC_FOR_TESTS,
    VERIFIER_SANDBOX_TIMEOUT_MS,
)
from app.telemetry.metrics import inc_sandbox, inc_sandbox_disagreement, observe_sandbox_latency

SandboxObs = Dict[str, Any]


async def _one_shadow_call(provider_name: str, text: str, meta: Dict[str, Any]) -> SandboxObs:
    """Run a single provider in a tight timebox; never raise."""
    prov = build_provider(provider_name)
    if prov is None:
        return {
            "provider": provider_name,
            "status": "error",
            "reason": "unavailable",
            "latency_s": 0.0,
        }

    async def _run() -> Dict[str, Any]:
        return await prov.assess(text, meta=meta)

    t0 = time.perf_counter()
    try:
        res: Dict[str, Any] = await asyncio.wait_for(
            _run(), timeout=max(0.05, VERIFIER_SANDBOX_TIMEOUT_MS / 1000.0)
        )
        status = str(res.get("status") or "ambiguous").lower()
        lat = time.perf_counter() - t0
        try:
            observe_sandbox_latency(provider_name, lat)
            inc_sandbox(provider_name, status)
        except Exception:
            pass
        return {
            "provider": provider_name,
            "status": status,
            "reason": str(res.get("reason") or ""),
            "latency_s": lat,
        }
    except asyncio.TimeoutError:
        lat = time.perf_counter() - t0
        try:
            observe_sandbox_latency(provider_name, lat)
            inc_sandbox(provider_name, "timeout")
        except Exception:
            pass
        return {
            "provider": provider_name,
            "status": "timeout",
            "reason": "sandbox_timeout",
            "latency_s": lat,
        }
    except Exception as e:  # noqa: BLE001
        lat = time.perf_counter() - t0
        try:
            observe_sandbox_latency(provider_name, lat)
            inc_sandbox(provider_name, "error")
        except Exception:
            pass
        return {
            "provider": provider_name,
            "status": "error",
            "reason": type(e).__name__,
            "latency_s": lat,
        }


async def run_sandbox_for_providers(
    providers: Iterable[str],
    text: str,
    meta: Dict[str, Any],
) -> List[SandboxObs]:
    """Run shadow calls for a small set of providers with bounded concurrency."""
    names = [p for p in providers if p]
    if not names:
        return []

    sem = asyncio.Semaphore(max(1, int(VERIFIER_SANDBOX_MAX_CONCURRENCY)))

    async def _guarded(name: str) -> SandboxObs:
        async with sem:
            return await _one_shadow_call(name, text, meta)

    results = await asyncio.gather(*[_guarded(n) for n in names], return_exceptions=False)
    # Cap results attached to audit/headers
    return results[: max(1, int(VERIFIER_SANDBOX_MAX_RESULTS))]


def should_run_sandbox() -> bool:
    if not VERIFIER_SANDBOX_ENABLED:
        return False
    try:
        return random.random() < float(VERIFIER_SANDBOX_SAMPLE_RATE)
    except Exception:
        return False


async def maybe_schedule_sandbox(
    primary: str,
    all_providers: List[str],
    text: str,
    meta: Dict[str, Any],
) -> Optional[List[SandboxObs]]:
    """
    If sampling hits, shadow-call alternate providers.
    - In production: fire-and-forget.
    - In tests (SYNC_FOR_TESTS=1): await and return results for assertions.
    """
    if not should_run_sandbox():
        return None

    others = [p for p in all_providers if p and p != primary]
    if not others:
        return None

    coro = run_sandbox_for_providers(others, text, meta)

    if VERIFIER_SANDBOX_SYNC_FOR_TESTS:
        return await coro

    # Fire-and-forget; shield so cancellation of the request doesn't kill sandbox
    try:
        asyncio.create_task(asyncio.shield(coro))  # type: ignore[arg-type]
    except Exception:
        # If scheduling fails, just ignore
        return None
    return None


def _is_decisive(status: str) -> bool:
    s = (status or "").lower()
    return s in ("safe", "unsafe")


def _diffs(primary_status: str, results: List[SandboxObs]) -> List[SandboxObs]:
    ps = (primary_status or "").lower()
    out: List[SandboxObs] = []
    for r in results:
        ss = (str(r.get("status") or "ambiguous")).lower()
        if ss != ps:
            out.append(r)
    return out


def _summarize(objs: List[SandboxObs], cap: int) -> str:
    cap = max(1, int(cap))
    parts = []
    for o in objs[:cap]:
        prov = str(o.get("provider") or "unknown")
        st = str(o.get("status") or "ambiguous")
        ms = int(float(o.get("latency_s") or 0.0) * 1000)
        parts.append(f"{prov}:{st}({ms}ms)")
    return ",".join(parts)


def analyze_and_surface_diffs(
    primary_provider: str,
    primary_status: str,
    sandbox_results: List[SandboxObs],
    tenant: str,
    bot: str,
) -> str | None:
    """
    Compare sandbox results with primary. Emit metrics and optionally return a
    compact string summary to be attached to headers/audit by the caller.
    Never raises.
    """
    if not VERIFIER_SANDBOX_DIFF_ENABLED:
        return None
    if VERIFIER_SANDBOX_DIFF_ONLY_ON_DECISIVE and not _is_decisive(primary_status):
        return None
    try:
        disagreements = _diffs(primary_status, sandbox_results)
        if not disagreements:
            return None

        # Metrics per disagreeing shadow
        for r in disagreements:
            inc_sandbox_disagreement(
                str(r.get("provider") or "unknown"),
                (primary_status or "ambiguous"),
                str(r.get("status") or "ambiguous"),
            )

        summary = _summarize(disagreements, VERIFIER_SANDBOX_DIFF_MAX_ATTACH)

        # Optional sampled audit record
        try:
            if VERIFIER_SANDBOX_DIFF_AUDIT_RATE > 0.0 and _rand.random() < float(
                VERIFIER_SANDBOX_DIFF_AUDIT_RATE
            ):
                emit_audit_event(
                    {
                        "event": "verifier_sandbox_disagreement",
                        "tenant_id": tenant,
                        "bot_id": bot,
                        "primary": {
                            "provider": primary_provider,
                            "status": primary_status,
                        },
                        "disagreements": disagreements[:VERIFIER_SANDBOX_DIFF_MAX_ATTACH],
                    }
                )
        except Exception:
            pass

        return summary if VERIFIER_SANDBOX_DIFF_ATTACH_HEADER else None
    except Exception:
        return None
