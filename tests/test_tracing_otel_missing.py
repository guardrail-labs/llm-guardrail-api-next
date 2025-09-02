import logging
import sys
from unittest.mock import patch

from app.telemetry.tracing import TracingMiddleware


class DummyApp:
    async def __call__(self, scope, receive, send):
        pass


def test_warn_and_initialize_when_opentelemetry_missing(monkeypatch, caplog):
    monkeypatch.setenv("OTEL_ENABLED", "true")
    tm = TracingMiddleware(DummyApp())
    assert tm.enabled is True
    with patch.dict(sys.modules, {"opentelemetry": None}):
        caplog.set_level(logging.WARNING)
        ok = tm._ensure_tracer_provider()
    assert ok is True
    assert tm._trace is None
    assert "opentelemetry is not installed" in caplog.text
