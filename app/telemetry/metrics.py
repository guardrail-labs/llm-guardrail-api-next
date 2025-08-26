from time import monotonic

from fastapi import FastAPI, Request, Response
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

# Secret redactions
REDACTIONS = Counter(
    "guardrail_redactions_total",
    "Total secret redactions by kind",
    ["kind"],
    registry=_registry,
)

# Rate limit rejections
RATE_LIMITED = Counter(
    "guardrail_rate_limited_total",
    "Total requests rejected due to rate limiting",
    registry=_registry,
)

# Audit events emitted
AUDIT_EVENTS = Counter(
    "guardrail_audit_events_total",
    "Total audit events emitted",
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


def inc_redaction(kind: str) -> None:
    REDACTIONS.labels(kind=kind).inc()


def inc_rate_limited() -> None:
    RATE_LIMITED.inc()


def inc_audit_event() -> None:
    AUDIT_EVENTS.inc()


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

