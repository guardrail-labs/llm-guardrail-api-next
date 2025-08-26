from time import monotonic

from fastapi import FastAPI, Response, Request
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Histogram,
    generate_latest,
)

_registry = CollectorRegistry(auto_describe=True)

# Requests hitting /guardrail
REQUESTS = Counter(
    "guardrail_requests_total",
    "Total guardrail requests",
    registry=_registry,
)

# Decisions emitted by policy
DECISIONS = Counter(
    "guardrail_decisions_total",
    "Total decisions by type",
    ["decision"],
    registry=_registry,
)

# Individual rule hits
RULE_HITS = Counter(
    "guardrail_rule_hits_total",
    "Total rule hits by rule_id",
    ["rule_id"],
    registry=_registry,
)

# Latency for /guardrail in seconds
LATENCY = Histogram(
    "guardrail_latency_seconds",
    "Latency of /guardrail requests in seconds",
    registry=_registry,
)


def inc_decision(decision: str) -> None:
    DECISIONS.labels(decision=decision).inc()


def inc_rule_hits(rule_ids: list[str]) -> None:
    for rid in rule_ids:
        RULE_HITS.labels(rule_id=rid).inc()


def setup_metrics(app: FastAPI) -> None:
    @app.middleware("http")
    async def metrics_middleware(request: Request, call_next):
        start = monotonic()
        response = await call_next(request)
        if request.url.path == "/guardrail":
            REQUESTS.inc()
            LATENCY.observe(monotonic() - start)
        return response

    @app.get("/metrics")
    def metrics() -> Response:
        data = generate_latest(_registry)
        return Response(content=data, media_type=CONTENT_TYPE_LATEST)
