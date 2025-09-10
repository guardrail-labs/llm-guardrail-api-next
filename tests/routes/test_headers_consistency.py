from __future__ import annotations

from typing import Any, Dict, Tuple

from fastapi.testclient import TestClient

from app.main import app
from app.routes import guardrail as gr

client = TestClient(app)


def _stub(decision: str, source: str, reason: str | None = None):
    async def _fake(**_: Any) -> Tuple[str, Dict[str, str]]:
        headers = {
            "X-Guardrail-Decision": decision,
            "X-Guardrail-Decision-Source": source,
        }
        if reason:
            headers["X-Guardrail-Reason"] = reason
        return decision, headers

    return _fake


def _assert_common(resp, red_header: str):
    assert resp.headers["X-Guardrail-Decision"]
    assert resp.headers["X-Guardrail-Decision-Source"]
    assert resp.headers["X-Guardrail-Policy-Version"]
    assert resp.headers[red_header]


def test_headers_on_ingress(monkeypatch):
    monkeypatch.setattr(gr, "_maybe_hardened_verify", _stub("allow", "verifier-live"))
    r = client.post(
        "/guardrail/evaluate",
        json={"text": "hi"},
        headers={"X-Tenant-ID": "t", "X-Bot-ID": "b"},
    )
    assert r.status_code == 200
    _assert_common(r, "X-Guardrail-Ingress-Redactions")


def test_headers_on_multipart(monkeypatch):
    monkeypatch.setattr(gr, "_maybe_hardened_verify", _stub("allow", "verifier-live", "ok"))
    r = client.post(
        "/guardrail/evaluate_multipart",
        data={"text": (None, "hi")},
        headers={"X-Tenant-ID": "t", "X-Bot-ID": "b"},
    )
    assert r.status_code == 200
    _assert_common(r, "X-Guardrail-Ingress-Redactions")
    assert r.headers["X-Guardrail-Reason"] == "ok"


def test_headers_on_egress(monkeypatch):
    monkeypatch.setattr(gr, "_maybe_hardened_verify", _stub("deny", "verifier-live"))
    r = client.post(
        "/guardrail/egress_evaluate",
        json={"text": "hello"},
        headers={"X-Tenant-ID": "t", "X-Bot-ID": "b"},
    )
    assert r.status_code == 200
    _assert_common(r, "X-Guardrail-Egress-Redactions")
