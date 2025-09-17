# tests/conftest.py
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.main import create_app  # noqa: E402


@pytest.fixture(autouse=True)
def _disable_rate_limit(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    try:
        import app.services.ratelimit as rl

        monkeypatch.setattr(rl, "_global_enabled", None, raising=False)
        monkeypatch.setattr(rl, "_global_limiter", None, raising=False)
    except Exception:
        pass


@pytest.fixture()
def app():
    # Function scope: new app for each test to pick up monkeypatched env.
    return create_app()


@pytest.fixture()
def client(app):
    with TestClient(app) as c:
        yield c
