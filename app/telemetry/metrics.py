from fastapi import FastAPI, Response
from prometheus_client import CollectorRegistry, CONTENT_TYPE_LATEST, generate_latest
from prometheus_client import Counter

_registry = CollectorRegistry(auto_describe=True)
REQUESTS = Counter("guardrail_requests_total", "Total guardrail requests", registry=_registry)

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
