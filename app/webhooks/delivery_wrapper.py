from __future__ import annotations

import asyncio
import time
from typing import Dict, Optional

import httpx

from app import settings
from app.runtime import get_redis
from app.webhooks.dlq import DeadLetterQueue
from app.webhooks.models import WebhookJob
from app.webhooks.retry import RetryQueue, compute_backoff_s


async def deliver_with_retry(
    url: str,
    method: str,
    headers: Dict[str, str],
    body: bytes,
) -> None:
    """
    Send once; on failure, schedule retries with backoff and start a singleton
    background worker if not already active. Caller is not blocked by retries.
    """
    r = get_redis()
    rq = RetryQueue(r, prefix=settings.WH_REDIS_PREFIX)
    dlq = DeadLetterQueue(r, prefix=settings.WH_REDIS_PREFIX)

    job = WebhookJob(
        url=url,
        method=method,
        headers=headers,
        body=body,
        attempt=1,
        created_at_s=time.time(),
        last_error=None,
    )

    ok, err = await _try_once(job)
    if ok:
        return

    err_msg = err or "unknown"
    await _schedule_retry(rq, job, err_msg)
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
    and release it when the schedule empties or renewal fails.
    """
    r = rq.redis
    prefix = rq.prefix
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
    Drain until schedule empty; sleep until next due; renew lock periodically.
    Stops immediately if renewal fails to preserve singleton guarantee.
    """
    renew_interval = max(1.0, min(lock_ttl_s / 2.0, 5.0))
    last_renew = 0.0

    async def _renew_if_needed() -> bool:
        nonlocal last_renew
        now_s = time.time()
        if now_s - last_renew >= renew_interval:
            ok = await redis.set(lock_key, lock_value, ex=int(lock_ttl_s), xx=True)
            if not ok:
                return False
            last_renew = now_s
        return True

    async def _with_attempt_renewal(coro) -> tuple[bool, Optional[str]]:
        """
        Run HTTP attempt while renewing lock on a short cadence to avoid expiry.
        If renewal fails mid-flight, cancel attempt and stop worker.
        """
        stop = asyncio.Event()
        failed = asyncio.Event()

        async def _ticker() -> None:
            tick = max(0.25, min(renew_interval / 2.0, 2.0))
            while not stop.is_set() and not failed.is_set():
                ok = await _renew_if_needed()
                if not ok:
                    failed.set()
                    break
                await asyncio.wait_for(asyncio.sleep(tick), timeout=tick + 0.1)

        t = asyncio.create_task(_ticker())
        try:
            result = await coro if not failed.is_set() else (False, "lock-lost")
        finally:
            stop.set()
            try:
                await t
            except Exception:  # noqa: BLE001
                pass

        if failed.is_set():
            # Lock lost mid-request; signal worker to stop
            raise RuntimeError("worker lock lost")
        return result

    while True:
        ok = await _renew_if_needed()
        if not ok:
            return

        _, jobs = await rq.pop_ready(limit=settings.WH_RETRY_DRAIN_BATCH)
        if jobs:
            for job in jobs:
                ok = await _renew_if_needed()
                if not ok:
                    return
                try:
                    ok_req, err = await _with_attempt_renewal(_try_once(job))
                except RuntimeError:
                    return  # lock lost mid-attempt
                if ok_req:
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
                    err_msg = err or "unknown"
                    await _schedule_retry(rq, job, err_msg)
            continue

        next_due = await rq.earliest_due_ts()
        if next_due is None:
            return

        sleep_s = max(0.0, next_due - time.time())
        end_s = time.time() + min(sleep_s, settings.WH_RETRY_IDLE_SLEEP_MAX_S)
        while True:
            ok = await _renew_if_needed()
            if not ok:
                return
            now_s = time.time()
            if now_s >= end_s:
                break
            await asyncio.sleep(min(0.5, end_s - now_s))
