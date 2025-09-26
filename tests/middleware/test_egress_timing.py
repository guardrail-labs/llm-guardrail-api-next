from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse
from starlette.testclient import TestClient

from app.middleware.egress_timing import EgressTimingMiddleware


def make_app() -> FastAPI:
    app = FastAPI()

    @app.get("/fast")
    async def fast_endpoint() -> PlainTextResponse:
        return PlainTextResponse("ok")

    @app.get("/sensitive")
    async def sensitive_endpoint(request: Request) -> PlainTextResponse:
        request.state.guardrail_sensitive = True
        return PlainTextResponse("ok")

    app.add_middleware(EgressTimingMiddleware)
    return app


def test_fast_endpoint_not_delayed(monkeypatch) -> None:
    calls: list[float] = []

    async def fake_sleep(duration: float) -> None:  # pragma: no cover - helper
        if duration > 0:
            calls.append(duration)

    monkeypatch.setattr("app.middleware.egress_timing.asyncio.sleep", fake_sleep)

    client = TestClient(make_app())
    response = client.get("/fast")
    assert response.status_code == 200
    assert calls == []


def test_sensitive_endpoint_delayed(monkeypatch) -> None:
    calls: list[float] = []

    async def fake_sleep(duration: float) -> None:  # pragma: no cover - helper
        if duration > 0:
            calls.append(duration)

    monkeypatch.setattr("app.middleware.egress_timing.asyncio.sleep", fake_sleep)
    monkeypatch.setattr("app.middleware.egress_timing.random.uniform", lambda *_: 0.0)

    class _PerfCounter:
        def __init__(self) -> None:
            self._calls = 0

        def __call__(self) -> float:
            self._calls += 1
            return 0.0

    monkeypatch.setattr("app.middleware.egress_timing.time.perf_counter", _PerfCounter())

    client = TestClient(make_app())
    response = client.get("/sensitive")
    assert response.status_code == 200
    assert len(calls) == 1
    assert calls[0] >= 0.15
