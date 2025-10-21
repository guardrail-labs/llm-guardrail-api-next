from __future__ import annotations

import asyncio
import time
from typing import Dict, Optional, Tuple

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
    asyncio.create_task(_drain_once(retry_queue, dlq))


async def _try_once(job: WebhookJob) -> Tuple[bool, Optional[str]]:
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


async def _drain_once(retry_queue: RetryQueue, dlq: DeadLetterQueue) -> None:
    while True:
        _, jobs = await retry_queue.pop_ready(limit=settings.WH_RETRY_DRAIN_BATCH)
        if not jobs:
            return
        for job in jobs:
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
