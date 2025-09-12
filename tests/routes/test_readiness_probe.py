# tests/routes/test_readiness_probe.py
# Summary: Readiness respects optional env-based verifier probe.

from __future__ import annotations

import asyncio

from starlette.testclient import TestClient

import app.main as main
import app.routes.system as sysmod


def test_ready_503_until_required_env_present(monkeypatch) -> None:
    # Enable probe; require SOME_KEY which we won't set initially.
    monkeypatch.setenv("PROBE_VERIFIER_ENABLED", "1")
    monkeypatch.setenv("PROBE_VERIFIER_REQUIRED_ENVS", "SOME_KEY")
    monkeypatch.setenv("PROBE_VERIFIER_INTERVAL_MS", "0")  # one-shot at startup
    monkeypatch.setenv("HEALTH_READY_DELAY_MS", "0")

    with TestClient(main.app) as client:
        r1 = client.get("/ready")
        assert r1.status_code == 503

    # Reset draining state so startup can run again
    sysmod._reset_readiness_for_tests()

    # Now satisfy the requirement and re-run probe (test helper)
    monkeypatch.setenv("SOME_KEY", "present")
    asyncio.run(sysmod._run_probe_once_for_tests())

    with TestClient(main.app) as client:
        r2 = client.get("/ready")
        assert r2.status_code == 200
        assert r2.json().get("ok") is True
    sysmod._reset_readiness_for_tests()


def test_ready_200_when_probe_enabled_and_env_present(monkeypatch) -> None:
    monkeypatch.setenv("PROBE_VERIFIER_ENABLED", "1")
    monkeypatch.setenv("PROBE_VERIFIER_REQUIRED_ENVS", "FOO_KEY,BAR_KEY")
    monkeypatch.setenv("FOO_KEY", "x")
    monkeypatch.setenv("BAR_KEY", "y")
    monkeypatch.setenv("HEALTH_READY_DELAY_MS", "0")
    monkeypatch.setenv("PROBE_VERIFIER_INTERVAL_MS", "0")

    sysmod._reset_readiness_for_tests()
    with TestClient(main.app) as client:
        r = client.get("/ready")
        assert r.status_code == 200
        assert r.json()["ok"] is True
    sysmod._reset_readiness_for_tests()
