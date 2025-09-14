from __future__ import annotations

import os
import re

from starlette.testclient import TestClient

os.environ.pop("PROMETHEUS_MULTIPROC_DIR", None)

from app.main import create_app
from app.services.verifier import _ROUTER  # singleton shim


def test_snapshot_is_capped_and_latest_kept(monkeypatch):
    # Keep memory bounded and deterministic for this test
    monkeypatch.setenv("VERIFIER_ROUTER_SNAPSHOT_MAX", "200")
    # Seed > cap entries
    for i in range(205):
        _ROUTER.rank("tenant-x", "bot-y", [str(i)])  # type: ignore[attr-defined]
    snaps = _ROUTER.get_last_order_snapshot()  # type: ignore[attr-defined]
    assert isinstance(snaps, list)
    assert len(snaps) == 200
    # Last entry should reflect the most recent rank
    assert snaps[-1]["order"] == ["204"]


def test_rank_metric_exposed(monkeypatch):
    # Enable /metrics endpoint
    monkeypatch.setenv("METRICS_ROUTE_ENABLED", "1")
    monkeypatch.delenv("PROMETHEUS_MULTIPROC_DIR", raising=False)

    c = TestClient(create_app())
    # Drive a couple of ranks to bump the counter
    _ROUTER.rank("acme", "chatbot-a", ["p1", "p2"])  # type: ignore[attr-defined]
    _ROUTER.rank("acme", "chatbot-a", ["p1", "p2"])  # type: ignore[attr-defined]

    r = c.get("/metrics")
    assert r.status_code == 200
    text = r.text

    # Look for our counter name; tolerate arbitrary labels order
    pat = re.compile(
        r'(?m)^verifier_router_rank_total\{[^}]*tenant="acme"[^}]*bot="chatbot-a"[^}]*\}\s+([0-9]+(?:\.[0-9]+)?)$'
    )
    m = pat.search(text)
    assert m, f"counter not found in metrics:\n{text[:500]}"
    # Count should be >= 2 (exact value may include other test runs in session)
    assert float(m.group(1)) >= 2.0
