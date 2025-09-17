from fastapi import FastAPI, Request
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
