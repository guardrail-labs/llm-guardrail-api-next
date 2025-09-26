from __future__ import annotations

import asyncio
import random
import time
from typing import Awaitable, Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware


class EgressTimingMiddleware(BaseHTTPMiddleware):
    """Normalize response timing to reduce side-channel leakage."""

    min_delay_sensitive = 0.150
    jitter_range = (0.0, 0.050)

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        start = time.perf_counter()
        response = await call_next(request)

        sensitive = getattr(request.state, "guardrail_sensitive", False)

        if sensitive:
            elapsed = time.perf_counter() - start
            target = self.min_delay_sensitive + random.uniform(*self.jitter_range)
            sleep_for = target - elapsed
            if sleep_for > 0:
                await asyncio.sleep(sleep_for)

        return response
