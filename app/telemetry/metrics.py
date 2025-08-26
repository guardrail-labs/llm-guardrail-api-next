from fastapi import FastAPI, Response
from prometheus_client import CollectorRegistry, CONTENT_TYPE_LATEST, generate_latest
from prometheus_client import Counter

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


def inc_decision(decision: str) -> None:
    DECISIONS.labels(decision=decision).inc()


def inc_rule_hits(rule_ids: list[str]) -> None:
    for rid in rule_ids:
        RULE_HITS.labels(rule_id=rid).inc()


def setup_metrics(app: FastAPI) -> None:
    @app.middleware("http")
    async def count_requests(request, call_next):
        response = await call_next(request)
        if request.url.path == "/guardrail":
            REQUESTS.inc()
        return response

    @app.get("/metrics")
    def metrics():
        data = generate_latest(_registry)
        return Response(content=data, media_type=CONTENT_TYPE_LATEST)
