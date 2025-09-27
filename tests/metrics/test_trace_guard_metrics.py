from __future__ import annotations


def _scrape_count(text: str, name: str) -> float:
    total = 0.0
    for line in text.splitlines():
        if line.startswith(name):
            try:
                total += float(line.rsplit(" ", 1)[-1])
            except Exception:
                pass
    return total


def test_reqid_generated_increments(client) -> None:
    before = client.get("/metrics")
    assert before.status_code == 200
    name = "guardrail_ingress_trace_request_id_generated_total"
    c0 = _scrape_count(before.text, name)

    response = client.get(
        "/health",
        headers={
            "X-Guardrail-Tenant": "acme",
            "X-Guardrail-Bot": "demo",
        },
    )
    assert response.status_code == 200

    after = client.get("/metrics")
    c1 = _scrape_count(after.text, name)
    assert c1 > c0


def test_invalid_traceparent_increments(client) -> None:
    before = client.get("/metrics")
    assert before.status_code == 200
    name = "guardrail_ingress_trace_invalid_traceparent_total"
    c0 = _scrape_count(before.text, name)

    bad_tp = "00-deadbeef-zzzz-nope"
    response = client.get("/health", headers={"traceparent": bad_tp})
    assert response.status_code == 200

    after = client.get("/metrics")
    c1 = _scrape_count(after.text, name)
    assert c1 > c0
