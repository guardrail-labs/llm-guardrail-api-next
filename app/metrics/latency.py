from __future__ import annotations

import time
from contextlib import contextmanager

from prometheus_client import Histogram

REQ_LATENCY = Histogram(
    "guardrail_request_seconds",
    "Request latency seconds",
    buckets=(0.05, 0.1, 0.2, 0.35, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0),
    labelnames=("path", "method"),
)


@contextmanager
def observe(path: str, method: str):
    start = time.perf_counter()
    try:
        yield
    finally:
        duration = time.perf_counter() - start
        REQ_LATENCY.labels(path=path, method=method).observe(duration)
