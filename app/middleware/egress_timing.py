# app/middleware/egress_timing.py
from __future__ import annotations

import asyncio
import os
import random
import time
from typing import Awaitable, Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware


class EgressTimingMiddleware(BaseHTTPMiddleware):
    """
    Normalize response times to reduce timing side-channel leakage.

    Behavior:
      - If request.state.guardrail_sensitive is True (set upstream by
        scanners/risk/probing), enforce a higher minimum delay plus jitter.
      - Optionally apply a tiny baseline jitter to all responses when the
        env var GUARDRAIL_TIMING_BASELINE=1 is set. Disabled by default so
        tests and low-latency paths remain unaffected.

    To mark a request as sensitive upstream:
        request.state.guardrail_sensitive = True
    """

    # Baseline jitter (opt-in via env)
    base_min_delay = 0.010  # 10 ms floor
    base_jitter_range = (0.0, 0.010)  # up to +10 ms random jitter
    enable_baseline = os.getenv("GUARDRAIL_TIMING_BASELINE", "0") == "1"

    # Stronger normalization for sensitive responses
    min_delay_sensitive = 0.150  # at least 150 ms total
    jitter_range = (0.0, 0.050)  # up to +50 ms random jitter

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        start = time.perf_counter()
        response = await call_next(request)

        sensitive = getattr(request.state, "guardrail_sensitive", False)

        # Baseline target only if enabled
        base_target = 0.0
        if self.enable_baseline:
            base_target = self.base_min_delay + random.uniform(*self.base_jitter_range)

        # If sensitive, raise the target delay
        if sensitive:
            sens_target = self.min_delay_sensitive + random.uniform(*self.jitter_range)
            target = max(base_target, sens_target)
        else:
            target = base_target

        elapsed = time.perf_counter() - start
        sleep_for = target - elapsed
        if sleep_for > 0:
            await asyncio.sleep(sleep_for)

        return response
