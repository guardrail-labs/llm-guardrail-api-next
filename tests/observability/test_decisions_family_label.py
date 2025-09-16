from starlette.testclient import TestClient


def test_guardrail_decisions_metric_uses_family_label() -> None:
    from app.main import create_app

    app = create_app()
    c = TestClient(app)

    r = c.post("/guardrail/evaluate", json={"text": "hello"}, headers={"X-Debug": "1"})
    assert r.status_code in (200, 400, 403, 429, 500)

    m = c.get("/metrics")
    assert m.status_code == 200
    body = m.text

    assert "guardrail_decisions_total" in body
    assert 'family="' in body, (
        f"Expected 'family' label for guardrail_decisions_total; got:\n{body[:2000]}"
    )
    assert "guardrail_decisions_total{family=" in body
    for line in body.splitlines():
        if line.startswith("guardrail_decisions_total{"):
            assert "action=" not in line

