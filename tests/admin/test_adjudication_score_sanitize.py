import json
from typing import Iterator

import pytest
from fastapi.testclient import TestClient

import app.observability.adjudication_log as adjudication_log
from app.routes import guardrail
from app.routes.guardrail import _coerce_score


@pytest.fixture
def admin_client(client: TestClient) -> Iterator[TestClient]:
    adjudication_log.clear()
    try:
        yield client
    finally:
        adjudication_log.clear()


def _admin_headers(key: str = "secret") -> dict[str, str]:
    return {"X-Admin-Key": key}


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_coerce_score_nonfinite_returns_none(value: float) -> None:
    assert _coerce_score(value) is None


def test_coerce_score_coerces_strings_and_bools() -> None:
    assert _coerce_score("0.42") == pytest.approx(0.42)
    assert _coerce_score(True) == pytest.approx(1.0)


@pytest.mark.parametrize("bad_score", [float("nan"), float("inf"), float("-inf")])
def test_admin_adjudications_sanitize_nonfinite_scores(
    admin_client: TestClient, monkeypatch: pytest.MonkeyPatch, bad_score: float
) -> None:
    original_finalize = guardrail._finalize_ingress_response

    def _fake_finalize(response, *, policy_result=None, **kwargs):
        if isinstance(policy_result, dict):
            policy_result["score"] = bad_score
        return original_finalize(
            response, policy_result=policy_result, **kwargs
        )

    monkeypatch.setattr(guardrail, "_finalize_ingress_response", _fake_finalize)

    response = admin_client.post("/guardrail/evaluate", json={"text": "hello"})
    assert response.status_code == 200

    listing = admin_client.get("/admin/adjudications", headers=_admin_headers())
    assert listing.status_code == 200
    items = listing.json()["items"]
    assert items, "expected adjudication records"
    assert items[0]["score"] is None

    export = admin_client.get(
        "/admin/adjudications/export.ndjson", headers=_admin_headers()
    )
    assert export.status_code == 200
    lines = [json.loads(line) for line in export.text.splitlines() if line.strip()]
    assert lines, "expected NDJSON entries"
    assert lines[0]["score"] is None
