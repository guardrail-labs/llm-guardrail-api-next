from __future__ import annotations

import re

from starlette.testclient import TestClient

from app.main import create_app
from app.services.verifier import _ROUTER  # singleton shim


def test_snapshot_is_capped_and_latest_kept(monkeypatch):
    monkeypatch.setenv("VERIFIER_ROUTER_SNAPSHOT_MAX", "200")
    for i in range(205):
        _ROUTER.rank("tenant-x", "bot-y", [str(i)])  # type: ignore[attr-defined]
    snaps = _ROUTER.get_last_order_snapshot()  # type: ignore[attr-defined]
    assert isinstance(snaps, list)
    assert len(snaps) == 200
    assert snaps[-1]["order"] == ["204"]


def test_rank_metric_exposed(monkeypatch):
    # Enable /metrics endpoint
    monkeypatch.setenv("METRICS_ROUTE_ENABLED", "1")

    # Drive a couple of ranks to bump the counter
    _ROUTER.rank("acme", "chatbot-a", ["p1", "p2"])  # type: ignore[attr-defined]
    _ROUTER.rank("acme", "chatbot-a", ["p1", "p2"])  # type: ignore[attr-defined]

    c = TestClient(create_app())
    r = c.get("/metrics")
    assert r.status_code == 200
    text = r.text

    pat = re.compile(
        r'(?m)^verifier_router_rank_total\{[^}]*tenant="acme"[^}]*bot="chatbot-a"[^}]*\}\s+([0-9]+(?:\.[0-9]+)?)$'
        r'|^verifier_router_rank_total\{[^}]*bot="chatbot-a"[^}]*tenant="acme"[^}]*\}\s+([0-9]+(?:\.[0-9]+)?)$'
    )
    m = pat.search(text)
    assert m, f"counter not found in metrics:\n{text[:500]}"
    val = m.group(1) or m.group(2)
    assert float(val) >= 2.0

