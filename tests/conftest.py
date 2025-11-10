# tests/conftest.py
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("IDEMP_REDIS_URL", "memory://")

from app.main import create_app  # noqa: E402


@pytest.fixture(autouse=True)
def _disable_rate_limit(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("IDEMP_REDIS_URL", "memory://")
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


@pytest.hookimpl(tryfirst=True)
def pytest_pyfunc_call(pyfuncitem: pytest.Function) -> bool | None:
    """Minimal asyncio support without requiring pytest-asyncio."""

    test_func = pyfuncitem.obj
    if asyncio.iscoroutinefunction(test_func):
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            call_kwargs = {
                name: pyfuncitem.funcargs[name] for name in pyfuncitem._fixtureinfo.argnames
            }
            loop.run_until_complete(test_func(**call_kwargs))
        finally:
            asyncio.set_event_loop(None)
            loop.close()
        return True
    return None
