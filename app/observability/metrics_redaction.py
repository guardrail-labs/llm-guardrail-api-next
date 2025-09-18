from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from prometheus_client import Counter as CounterType
else:
    CounterType = Any

_prom_client: Any = None
try:  # pragma: no cover
    import prometheus_client as _prom_client
except Exception:  # pragma: no cover
    _prom_client = None

_ENABLED = os.getenv("METRICS_ENABLED", "true").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)

_skip_ctr: Optional[CounterType] = None
_bytes_ctr: Optional[CounterType] = None
_overlap_ctr: Optional[CounterType] = None


def _get_skip_ctr():
    global _skip_ctr
    if not _ENABLED or _prom_client is None:
        return None
    counter_cls = getattr(_prom_client, "Counter", None)
    if counter_cls is None:
        return None
    if _skip_ctr is None:
        _skip_ctr = counter_cls(
            "guardrail_egress_redactions_skipped_total",
            "Number of responses where egress redaction was skipped",
            ["reason"],
        )
    return _skip_ctr


def inc_skipped(reason: str) -> None:
    counter = _get_skip_ctr()
    if counter is None:
        return
    try:
        counter.labels(reason=reason).inc()
    except Exception:
        pass


def _get_bytes_ctr():
    global _bytes_ctr
    if not _ENABLED or _prom_client is None:
        return None
    counter_cls = getattr(_prom_client, "Counter", None)
    if counter_cls is None:
        return None
    if _bytes_ctr is None:
        _bytes_ctr = counter_cls(
            "guardrail_egress_redactions_bytes_scanned_total",
            "Total bytes scanned by egress redaction",
            [],
        )
    return _bytes_ctr


def add_scanned(n: int) -> None:
    counter = _get_bytes_ctr()
    if counter is None:
        return
    try:
        counter.inc(max(int(n), 0))
    except Exception:
        pass


def _get_overlap_ctr():
    global _overlap_ctr
    if not _ENABLED or _prom_client is None:
        return None
    counter_cls = getattr(_prom_client, "Counter", None)
    if counter_cls is None:
        return None
    if _overlap_ctr is None:
        _overlap_ctr = counter_cls(
            "guardrail_egress_redactions_window_overlaps_total",
            "Count of overlap windows applied during streaming redaction",
            [],
        )
    return _overlap_ctr


def inc_overlap() -> None:
    counter = _get_overlap_ctr()
    if counter is None:
        return
    try:
        counter.inc()
    except Exception:
        pass
