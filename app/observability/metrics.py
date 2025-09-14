# app/observability/metrics.py
from __future__ import annotations

from threading import Lock
from typing import Dict, Iterable, Tuple

from prometheus_client import REGISTRY, Counter, Histogram

# Known metric names → canonical labelnames (predeclared to avoid dup TS)
_CANON_LABELS: Dict[str, Tuple[str, ...]] = {
    # Hybrid-12: rank activity per tenant/bot
    "verifier_router_rank_total": ("tenant", "bot"),
    # You can predeclare more names here as needed, e.g.:
    # "verifier_router_success_total": ("provider",),
    # "verifier_router_failure_total": ("provider", "reason"),
}

# Caches of collectors keyed by (name, labelnames_tuple)
_COUNTERS: Dict[Tuple[str, Tuple[str, ...]], Counter] = {}
_HISTOS: Dict[Tuple[str, Tuple[str, ...]], Histogram] = {}
_LOCK = Lock()


def _labels_for(name: str, labels: Dict[str, str]) -> Tuple[str, ...]:
    if name in _CANON_LABELS:
        return _CANON_LABELS[name]
    # Fallback: freeze the exact labelnames used on first creation
    return tuple(sorted(labels.keys()))


def inc_counter(
    name: str,
    labels: Dict[str, str] | None = None,
    amount: float = 1.0,
    help_text: str | None = None,
) -> None:
    """
    Increment (or create-then-increment) a Counter in the SAME registry
    that /metrics exports (prometheus_client.REGISTRY). Label set is
    canonicalized by _CANON_LABELS to prevent duplicated time series.
    """
    if labels is None:
        labels = {}
    labelnames = _labels_for(name, labels)

    with _LOCK:
        key = (name, labelnames)
        counter = _COUNTERS.get(key)
        if counter is None:
            # Use name as help if not provided; short & harmless.
            counter = Counter(
                name,
                help_text or name.replace("_", " "),
                labelnames=labelnames,
                registry=REGISTRY,
            )
            _COUNTERS[key] = counter

    # Ensure we pass exactly the canonical label set
    if labelnames:
        # Fill any missing canonical labels with "unknown"
        filled = {ln: labels.get(ln, "unknown") for ln in labelnames}
        counter.labels(**filled).inc(amount)
    else:
        counter.inc(amount)


def observe_histogram(
    name: str,
    value: float,
    labels: Dict[str, str] | None = None,
    buckets: Iterable[float] | None = None,
    help_text: str | None = None,
) -> None:
    """
    Same pattern as inc_counter but for Histogram.
    """
    if labels is None:
        labels = {}
    labelnames = _labels_for(name, labels)
    with _LOCK:
        key = (name, labelnames)
        hist = _HISTOS.get(key)
        if hist is None:
            hist = Histogram(
                name,
                help_text or name.replace("_", " "),
                labelnames=labelnames,
                buckets=tuple(buckets) if buckets is not None else Histogram.DEFAULT_BUCKETS,
                registry=REGISTRY,
            )
            _HISTOS[key] = hist

    if labelnames:
        filled = {ln: labels.get(ln, "unknown") for ln in labelnames}
        hist.labels(**filled).observe(value)
    else:
        hist.observe(value)
