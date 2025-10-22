from __future__ import annotations

from typing import Any

Counter: Any
Gauge: Any

try:  # pragma: no cover - optional dependency
    from prometheus_client import Counter as _CounterImpl, Gauge as _GaugeImpl
except Exception:  # pragma: no cover - fallback when metrics disabled
    Counter = None
    Gauge = None
else:
    Counter = _CounterImpl
    Gauge = _GaugeImpl

__all__ = [
    "STREAM_SESSIONS",
    "STREAM_ACTIVE",
    "STREAM_BYTES",
    "STREAM_HEARTBEATS",
    "STREAM_DISCONNECTS",
]


class _NoopMetric:
    def labels(self, *_args: object, **_kwargs: object) -> "_NoopMetric":
        return self

    def inc(self, _value: float = 1.0) -> None:
        return None

    def set(self, _value: float) -> None:
        return None


def _counter(name: str, description: str, labels: tuple[str, ...]) -> Any:
    if Counter is None:  # pragma: no cover - runtime without prometheus
        return _NoopMetric()
    return Counter(name, description, list(labels))


def _gauge(name: str, description: str, labels: tuple[str, ...]) -> Any:
    if Gauge is None:  # pragma: no cover - runtime without prometheus
        return _NoopMetric()
    return Gauge(name, description, list(labels))


_STREAM_LABELS = ("route",)

STREAM_SESSIONS = _counter(
    "stream_sessions_total",
    "Count of SSE sessions initiated",
    _STREAM_LABELS,
)
STREAM_ACTIVE = _gauge(
    "stream_sessions_active",
    "Current active SSE sessions",
    _STREAM_LABELS,
)
STREAM_BYTES = _counter(
    "stream_bytes_total",
    "Bytes emitted over SSE",
    _STREAM_LABELS,
)
STREAM_HEARTBEATS = _counter(
    "stream_heartbeats_total",
    "Heartbeat frames emitted",
    _STREAM_LABELS,
)
STREAM_DISCONNECTS = _counter(
    "stream_disconnects_total",
    "Client disconnect notifications",
    _STREAM_LABELS,
)
