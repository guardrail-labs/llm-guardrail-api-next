import importlib
from fastapi.testclient import TestClient


def _client(monkeypatch):
    import app.routes.openai_compat as compat
    # ensure deterministic policies by allowing everything
    monkeypatch.setattr(compat, "sanitize_text", lambda text, debug=False: (text, [], 0, {}))
    monkeypatch.setattr(compat, "evaluate_prompt", lambda text: {"action": "allow", "rule_hits": [], "decisions": []})

    import app.telemetry.metrics as metrics
    importlib.reload(metrics)
    import app.main as main
    importlib.reload(main)
    return TestClient(main.app)


def test_images_generations_basic(monkeypatch):
    c = _client(monkeypatch)
    headers = {
        "X-API-Key": "k",
        "X-Tenant-ID": "acme",
        "X-Bot-ID": "assistant-1",
        "Content-Type": "application/json",
    }
    r = c.post(
        "/v1/images/generations",
        json={"prompt": "a cat", "n": 1},
        headers=headers,
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["data"] and data["data"][0]["b64_json"]
    # guard headers present
    assert r.headers.get("X-Guardrail-Policy-Version")
    assert r.headers.get("X-Guardrail-Ingress-Action") == "allow"
    assert r.headers.get("X-Guardrail-Egress-Action") == "allow"
