from fastapi.testclient import TestClient


def test_chat_completions_response_includes_decision_headers(client: TestClient) -> None:
    response = client.post("/guardrail/evaluate", json={"text": "hello"})
    assert response.status_code == 200

    decision = response.headers.get("X-Guardrail-Decision")
    mode = response.headers.get("X-Guardrail-Mode")
    incident = response.headers.get("X-Guardrail-Incident-ID")

    assert decision
    assert mode
    assert incident
