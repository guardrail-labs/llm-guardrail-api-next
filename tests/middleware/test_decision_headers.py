import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from app.middleware.decision_headers import DecisionHeaderMiddleware


def _app_with_route_sets_state() -> FastAPI:
    app = FastAPI()
    app.add_middleware(DecisionHeaderMiddleware)

    @app.get("/decide")
    def decide(request: Request):
        request.state.guardrail_decision = {
            "outcome": "execute_locked",
            "mode": "Tier2",
            "incident_id": "inc-123",
        }
        return {"ok": True}

    return app


def test_headers_from_request_state() -> None:
    app = _app_with_route_sets_state()
    client = TestClient(app)
    response = client.get("/decide")
    assert response.status_code == 200
    assert response.headers.get("X-Guardrail-Decision") == "execute_locked"
    assert response.headers.get("X-Guardrail-Mode") == "Tier2"
    assert response.headers.get("X-Guardrail-Incident-ID") == "inc-123"


def test_mode_defaults_to_runtime_when_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    app = FastAPI()
    app.add_middleware(DecisionHeaderMiddleware)

    @app.get("/deny")
    def deny(request: Request) -> JSONResponse:
        request.state.guardrail_decision = {"outcome": "deny"}
        return JSONResponse({"error": "nope"}, status_code=400)

    class _DummyMode:
        header_value = "egress-only"

    class _DummyRuntime:
        def __init__(self) -> None:
            self.mode = _DummyMode()

        def evaluate_mode(self) -> _DummyMode:
            return self.mode

    monkeypatch.setattr(
        "app.middleware.decision_headers._get_arm_runtime",
        lambda: _DummyRuntime(),
        raising=False,
    )

    client = TestClient(app)
    response = client.get("/deny")
    assert response.status_code == 400
    assert response.headers.get("X-Guardrail-Decision") == "deny"
    assert response.headers.get("X-Guardrail-Mode") == "egress-only"


def test_mode_header_emitted_for_404(monkeypatch: pytest.MonkeyPatch) -> None:
    app = FastAPI()
    app.add_middleware(DecisionHeaderMiddleware)

    class _DummyMode:
        header_value = "normal"

    class _DummyRuntime:
        def __init__(self) -> None:
            self.mode = _DummyMode()

        def evaluate_mode(self) -> _DummyMode:
            return self.mode

    runtime = _DummyRuntime()

    monkeypatch.setattr(
        "app.middleware.decision_headers._get_arm_runtime",
        lambda: runtime,
        raising=False,
    )

    client = TestClient(app)
    response = client.get("/missing")
    assert response.status_code == 404
    assert response.headers.get("X-Guardrail-Mode") == "normal"
