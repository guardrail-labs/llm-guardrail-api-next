from __future__ import annotations

from prometheus_client import Counter, Gauge

stream_sessions_total = Counter("stream_sessions_total", "Total stream sessions", ["route"])
stream_active_sessions = Gauge("stream_active_sessions", "Active stream sessions", ["route"])
stream_bytes_sent_total = Counter(
    "stream_bytes_sent_total", "Total bytes sent over streams", ["route"]
)
stream_disconnects_total = Counter(
    "stream_disconnects_total", "Stream disconnects", ["route", "reason"]
)
stream_heartbeat_total = Counter("stream_heartbeat_total", "Heartbeats sent", ["route"])
