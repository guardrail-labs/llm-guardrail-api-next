# Summary: Readiness respects optional env-based verifier probe.

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

import app.main as main
import app.routes.system as sysmod


def test_startup_fails_when_required_env_missing(monkeypatch) -> None:
    monkeypatch.setenv("PROBE_VERIFIER_ENABLED", "1")
    monkeypatch.setenv("PROBE_VERIFIER_REQUIRED_ENVS", "SOME_KEY")
    sysmod._reset_readiness_for_tests()
    with pytest.raises(RuntimeError):
        with TestClient(main.app):
            pass
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
