# tests/conftest.py
from __future__ import annotations

import pytest
from starlette.testclient import TestClient

try:
    # Prefer project app factory
    from app.main import create_app  # type: ignore
except Exception as e:  # pragma: no cover
    raise RuntimeError(
        "Could not import app.main.create_app; ensure the app factory exists."
    ) from e

@pytest.fixture(scope="session")
def app():
    return create_app()

@pytest.fixture()
def client(app):
    with TestClient(app) as c:
        yield c
