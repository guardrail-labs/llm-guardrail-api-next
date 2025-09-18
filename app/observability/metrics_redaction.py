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
