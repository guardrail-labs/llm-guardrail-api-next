from __future__ import annotations

import asyncio
import time
from typing import Dict, Optional

import httpx
from redis.asyncio import Redis

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
    Fire-and-manage: send once now; on failure, schedule retries with backoff.
    After MAX attempts, push to DLQ. Non-blocking beyond the first attempt.
    """
    redis = get_redis()
    retry_queue = RetryQueue(redis, prefix=settings.WH_REDIS_PREFIX)
    dlq = DeadLetterQueue(redis, prefix=settings.WH_REDIS_PREFIX)

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

    await _schedule_retry(retry_queue, first, err)
    asyncio.create_task(_ensure_worker(retry_queue, dlq))


async def _try_once(job: WebhookJob) -> tuple[bool, Optional[str]]:
    timeout_s = settings.WH_HTTP_TIMEOUT_S
    try:
        async with httpx.AsyncClient(timeout=timeout_s) as client:
            request = client.build_request(
                method=job.method,
                url=job.url,
                headers=job.headers,
                content=job.body,
            )
            response = await client.send(request)
            if 200 <= response.status_code < 300:
                return True, None
            return False, f"status={response.status_code}"
    except Exception as exc:  # noqa: BLE001
        return False, f"exc={type(exc).__name__}:{exc}"


async def _schedule_retry(
    retry_queue: RetryQueue, job: WebhookJob, err: Optional[str]
) -> None:
    backoff = compute_backoff_s(
        base_s=settings.WH_RETRY_BASE_S,
        factor=settings.WH_RETRY_FACTOR,
        attempt=job.attempt,
        jitter_s=settings.WH_RETRY_JITTER_S,
    )
    due = backoff + time.time()
    err_msg = err or "unknown"
    next_job = WebhookJob(
        url=job.url,
        method=job.method,
        headers=job.headers,
        body=job.body,
        attempt=job.attempt + 1,
        created_at_s=job.created_at_s,
        last_error=err_msg,
    )
    await retry_queue.enqueue(next_job, due)


async def _ensure_worker(retry_queue: RetryQueue, dlq: DeadLetterQueue) -> None:
    """Ensure a single worker per prefix using a Redis lock."""

    redis = retry_queue.redis
    prefix = retry_queue.prefix
    lock_key = f"{prefix}:worker:lock"
    lock_ttl_s = max(5.0, float(settings.WH_WORKER_LOCK_TTL_S))
    lock_value = str(time.time())

    acquired = await redis.set(lock_key, lock_value, ex=int(lock_ttl_s), nx=True)
    if not acquired:
        return

    try:
        await _drain_loop(retry_queue, dlq, redis, lock_key, lock_value, lock_ttl_s)
    finally:
        current = await redis.get(lock_key)
        if current is not None and current.decode("utf-8") == lock_value:
            await redis.delete(lock_key)


async def _drain_loop(
    retry_queue: RetryQueue,
    dlq: DeadLetterQueue,
    redis: Redis,
    lock_key: str,
    lock_value: str,
    lock_ttl_s: float,
) -> None:
    """Process ready jobs while renewing the singleton lock."""

    renew_interval = max(1.0, min(lock_ttl_s / 2.0, 5.0))
    last_renew = time.time()

    async def _renew_if_needed() -> bool:
        nonlocal last_renew
        now_s = time.time()
        if now_s - last_renew >= renew_interval:
            ok = await redis.set(lock_key, lock_value, ex=int(lock_ttl_s), xx=True)
            if not ok:
                return False
            last_renew = now_s
        return True

    while True:
        if not await _renew_if_needed():
            return

        _, jobs = await retry_queue.pop_ready(limit=settings.WH_RETRY_DRAIN_BATCH)
        if jobs:
            for job in jobs:
                if not await _renew_if_needed():
                    return
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
                            last_error=err or "unknown",
                        )
                    )
                else:
                    await _schedule_retry(retry_queue, job, err)
            continue

        next_due = await retry_queue.earliest_due_ts()
        if next_due is None:
            return

        target_sleep = min(
            max(0.0, next_due - time.time()), settings.WH_RETRY_IDLE_SLEEP_MAX_S
        )
        if target_sleep <= 0:
            continue
        end_s = time.time() + target_sleep
        while True:
            if not await _renew_if_needed():
                return
            now_s = time.time()
            if now_s >= end_s:
                break
            await asyncio.sleep(min(0.5, end_s - now_s))
