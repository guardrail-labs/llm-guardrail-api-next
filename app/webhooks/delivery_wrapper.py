from __future__ import annotations

import asyncio
import httpx
import time
from typing import Dict, Optional

from app import settings
from app.runtime import get_redis
from app.webhooks.models import WebhookJob
from app.webhooks.retry import RetryQueue, compute_backoff_s
from app.webhooks.dlq import DeadLetterQueue


async def deliver_with_retry(
    url: str,
    method: str,
    headers: Dict[str, str],
    body: bytes,
) -> None:
    """
    Fire-and-manage: send once now; on failure, schedule retries with backoff.
    After MAX attempts, push to DLQ. Non-blocking beyond the first attempt.
    """
    r = get_redis()
    rq = RetryQueue(r, prefix=settings.WH_REDIS_PREFIX)
    dlq = DeadLetterQueue(r, prefix=settings.WH_REDIS_PREFIX)

    first = WebhookJob(
        url=url,
        method=method,
        headers=headers,
        body=body,
        attempt=1,
        created_at_s=time.time(),
        last_error=None,
    )

    ok, err = await _try_once(first)
    if ok:
        return

    await _schedule_retry(rq, first, err)

    # Start a singleton worker if not already active for this prefix.
    asyncio.create_task(_ensure_worker(rq, dlq))


async def _try_once(job: WebhookJob) -> tuple[bool, Optional[str]]:
    timeout_s = settings.WH_HTTP_TIMEOUT_S
    try:
        async with httpx.AsyncClient(timeout=timeout_s) as client:
            req = client.build_request(
                method=job.method,
                url=job.url,
                headers=job.headers,
                content=job.body,
            )
            resp = await client.send(req)
            if 200 <= resp.status_code < 300:
                return True, None
            return False, f"status={resp.status_code}"
    except Exception as e:  # noqa: BLE001
        return False, f"exc={type(e).__name__}:{e}"


async def _schedule_retry(rq: RetryQueue, job: WebhookJob, err: str) -> None:
    backoff = compute_backoff_s(
        base_s=settings.WH_RETRY_BASE_S,
        factor=settings.WH_RETRY_FACTOR,
        attempt=job.attempt,
        jitter_s=settings.WH_RETRY_JITTER_S,
    )
    due = backoff + time.time()
    nxt = WebhookJob(
        url=job.url,
        method=job.method,
        headers=job.headers,
        body=job.body,
        attempt=job.attempt + 1,
        created_at_s=job.created_at_s,
        last_error=err,
    )
    await rq.enqueue(nxt, due)


async def _ensure_worker(rq: RetryQueue, dlq: DeadLetterQueue) -> None:
    """
    Acquire a Redis lock to ensure a single worker per prefix. If lock held by
    another process, exit. If acquired, run the drain loop, renewing the lock,
    and release it when the schedule empties.
    """
    r = rq._r  # noqa: SLF001
    prefix = rq._prefix  # noqa: SLF001
    lock_key = f"{prefix}:worker:lock"
    lock_ttl_s = max(5.0, float(settings.WH_WORKER_LOCK_TTL_S))
    lock_value = str(time.time())

    ok = await r.set(lock_key, lock_value, ex=int(lock_ttl_s), nx=True)
    if not ok:
        return

    try:
        await _drain_loop(rq, dlq, r, lock_key, lock_value, lock_ttl_s)
    finally:
        cur = await r.get(lock_key)
        if cur is not None and cur.decode("utf-8") == lock_value:
            await r.delete(lock_key)


async def _drain_loop(
    rq: RetryQueue,
    dlq: DeadLetterQueue,
    redis,
    lock_key: str,
    lock_value: str,
    lock_ttl_s: float,
) -> None:
    """
    Drain jobs until schedule empty; sleep until next due; renew lock frequently.
    Renewal occurs at top of loop and during job iteration to avoid expiry.
    """
    # Renew at most every this many seconds (half TTL, capped at 5s).
    renew_interval = max(1.0, min(lock_ttl_s / 2.0, 5.0))
    last_renew = 0.0

    async def _renew_if_needed() -> None:
        nonlocal last_renew
        now_s = time.time()
        if now_s - last_renew >= renew_interval:
            await redis.set(lock_key, lock_value, ex=int(lock_ttl_s), xx=True)
            last_renew = now_s

    while True:
        await _renew_if_needed()

        _, jobs = await rq.pop_ready(limit=settings.WH_RETRY_DRAIN_BATCH)
        if jobs:
            for job in jobs:
                await _renew_if_needed()
                ok, err = await _try_once(job)
                if ok:
                    continue
                if job.attempt >= settings.WH_MAX_ATTEMPTS:
                    await dlq.push(
                        WebhookJob(
                            url=job.url,
                            method=job.method,
                            headers=job.headers,
                            body=job.body,
                            attempt=job.attempt,
                            created_at_s=job.created_at_s,
                            last_error=err,
                        )
                    )
                else:
                    await _schedule_retry(rq, job, err)
            # Loop immediately to check for more ready work.
            continue

        next_due = await _next_due_ts(rq)
        if next_due is None:
            return

        # Sleep until next due (bounded) and keep lock fresh while waiting.
        sleep_s = max(0.0, next_due - time.time())
        end_s = time.time() + min(sleep_s, settings.WH_RETRY_IDLE_SLEEP_MAX_S)
        while True:
            await _renew_if_needed()
            now_s = time.time()
            if now_s >= end_s:
                break
            await asyncio.sleep(min(0.5, end_s - now_s))


async def _next_due_ts(rq: RetryQueue) -> Optional[float]:
    """
    Return earliest due timestamp (score) in schedule, or None if empty.
    """
    key = rq._sched_key()  # noqa: SLF001
    r = rq._r  # noqa: SLF001
    items = await r.zrange(key, 0, 0, withscores=True)
    if not items:
        return None
    return float(items[0][1])
