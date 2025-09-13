import importlib
import logging

from fastapi.testclient import TestClient

import app.main
from app.middleware.json_logging import JsonFormatter


def test_json_logging_installer(caplog):
    importlib.reload(app.main)
    client = TestClient(app.main.app)

    with caplog.at_level(logging.INFO):
        client.get("/health")

    root = logging.getLogger()
    assert len(root.handlers) == 1
    assert isinstance(root.handlers[0].formatter, JsonFormatter)

    importlib.reload(app.main)
    assert len(logging.getLogger().handlers) == 1
