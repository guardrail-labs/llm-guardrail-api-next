# tests/routes/test_metrics_route.py
# Summary: /metrics is 404 when disabled; 200 when enabled; honors API key if set.

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

import app.main as main


def _prom_or_skip() -> None:
    pytest.importorskip("prometheus_client")


def test_metrics_404_when_disabled(monkeypatch) -> None:
    _prom_or_skip()
    monkeypatch.setenv("METRICS_ROUTE_ENABLED", "0")
    client = TestClient(main.app)
    r = client.get("/metrics")
    assert r.status_code == 404


def test_metrics_200_when_enabled_without_key(monkeypatch) -> None:
    _prom_or_skip()
    monkeypatch.setenv("METRICS_ROUTE_ENABLED", "1")
    monkeypatch.delenv("METRICS_API_KEY", raising=False)
    client = TestClient(main.app)
    r = client.get("/metrics", headers={"Accept": "*/*"})
    assert r.status_code == 200
    ctype = r.headers.get("content-type", "")
    assert "text/plain" in ctype and "version=0.0.4" in ctype
    # Basic sanity: body is non-empty
    assert len(r.content) > 0


def test_metrics_requires_key_when_configured(monkeypatch) -> None:
    _prom_or_skip()
    monkeypatch.setenv("METRICS_ROUTE_ENABLED", "1")
    monkeypatch.setenv("METRICS_API_KEY", "sekret")
    client = TestClient(main.app)

    # Missing key -> 401
    r1 = client.get("/metrics")
    assert r1.status_code == 401

    # Wrong key -> 401
    r2 = client.get("/metrics", headers={"X-API-KEY": "nope"})
    assert r2.status_code == 401

    # Correct via X-API-KEY -> 200
    r3 = client.get("/metrics", headers={"X-API-KEY": "sekret"})
    assert r3.status_code == 200

    # Correct via Bearer -> 200
    r4 = client.get("/metrics", headers={"Authorization": "Bearer sekret"})
    assert r4.status_code == 200
