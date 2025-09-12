# tests/routes/test_readiness_drain.py
# Summary: /ready returns 200 after startup and 503 when draining/shutdown.

from __future__ import annotations

from starlette.testclient import TestClient

import app.main as main
import app.routes.system as sysmod


def test_ready_flips_to_503_when_draining(monkeypatch) -> None:
    # Ensure there is no startup delay so app is immediately ready in tests.
    monkeypatch.setenv("HEALTH_READY_DELAY_MS", "0")
    with TestClient(main.app) as client:
        r1 = client.get("/ready")
        assert r1.status_code == 200
        assert r1.json().get("ok") is True

        # Simulate shutdown/draining
        sysmod._enter_draining_for_tests()
        r2 = client.get("/ready")
        assert r2.status_code == 503
        assert r2.json().get("ok") is False

        # Reset so other tests aren't affected
        sysmod._reset_readiness_for_tests()
