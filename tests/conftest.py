# tests/conftest.py
from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from app.main import create_app


@pytest.fixture()
def app():
    # Function scope: new app for each test to pick up monkeypatched env.
    return create_app()


@pytest.fixture()
def client(app):
    with TestClient(app) as c:
        yield c
