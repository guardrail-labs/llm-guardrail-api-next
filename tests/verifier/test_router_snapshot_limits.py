from __future__ import annotations

import re

from starlette.testclient import TestClient

from app.main import create_app
from app.services.verifier import _ROUTER  # singleton shim


def test_snapshot_is_capped_and_latest_kept(monkeypatch) -> None:
    monkeypatch.setenv("VERIFIER_ROUTER_SNAPSHOT_MAX", "200")

    for i in range(205):
        _ROUTER.rank("tenant-x", "bot-y", [str(i)])

    snaps = _ROUTER.get_last_order_snapshot()
    assert isinstance(snaps, list)
    assert len(snaps) == 200
    # Last entry should reflect the most recent rank
    assert snaps[-1]["order"] == ["204"]


def test_rank_metric_exposed(monkeypatch) -> None:
    # Enable /metrics endpoint
    monkeypatch.setenv("METRICS_ROUTE_ENABLED", "1")

    # Drive a couple of ranks to bump the counter
    _ROUTER.rank("acme", "chatbot-a", ["p1", "p2"])
    _ROUTER.rank("acme", "chatbot-a", ["p1", "p2"])

    c = TestClient(create_app())
    r = c.get("/metrics")
    assert r.status_code == 200
    text = r.text

    # Tolerate arbitrary label order
    pat = re.compile(
        r'(?m)^verifier_router_rank_total\{[^}]*tenant="acme"[^}]*bot="chatbot-a"[^}]*\}'
        r"\s+([0-9]+(?:\.[0-9]+)?)$"
    )
    m = pat.search(text)
    assert m, f"counter not found in metrics:\n{text[:500]}"
    # Count should be >= 2 (exact value may include other tests in session)
    assert float(m.group(1)) >= 2.0
