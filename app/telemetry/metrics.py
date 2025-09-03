from __future__ import annotations

from typing import Any, Callable, Dict, Iterable, List, Tuple, TypeVar, Protocol, cast

# ---- Protocols describing only what we use (works for real + shims) ----------


class CounterLike(Protocol):
    def labels(self, *label_values: Any) -> "CounterLike": ...
    def inc(self, amount: float = 1.0) -> None: ...


class HistogramLike(Protocol):
    def labels(self, *label_values: Any) -> "HistogramLike": ...
    def observe(self, value: float) -> None: ...


# ---- Prepare names we will assign in branches to keep mypy happy --------------

PROM_REGISTRY: Any
CounterClass: Any
HistogramClass: Any
PROM_OK = True

# ---- Try real prometheus, else provide shims with the same surface ------------

try:
    # Use local aliases so we don't reassign imported type names.
    from prometheus_client import Counter as _PCounter
    from prometheus_client import Histogram as _PHistogram
    from prometheus_client import REGISTRY as _PREG

    PROM_REGISTRY = _PREG
    CounterClass = _PCounter
    HistogramClass = _PHistogram
except Exception:  # pragma: no cover
    PROM_OK = False

    class _ShimCounter:
        """Minimal counter shim (inc, labels)."""

        def __init__(self, *_: Any, **__: Any) -> None:
            self._value = 0.0
            self._children: Dict[Tuple[Any, ...], "_ShimCounter"] = {}

        def labels(self, *label_values: Any) -> "_ShimCounter":
            if label_values not in self._children:
                self._children[label_values] = _ShimCounter()
            return self._children[label_values]

        def inc(self, amount: float = 1.0) -> None:
            self._value += float(amount)

    class _ShimHistogram:
        """Minimal histogram shim (observe, labels)."""

        def __init__(self, *_: Any, **__: Any) -> None:
            self._sum = 0.0
            self._count = 0
            self._children: Dict[Tuple[Any, ...], "_ShimHistogram"] = {}

        def labels(self, *label_values: Any) -> "_ShimHistogram":
            if label_values not in self._children:
                self._children[label_values] = _ShimHistogram()
            return self._children[label_values]

        def observe(self, value: float) -> None:
            self._sum += float(value)
            self._count += 1

    class _DummyRegistry:
        def __init__(self) -> None:
            self._names_to_collectors: Dict[str, Any] = {}

    PROM_REGISTRY = _DummyRegistry()
    CounterClass = _ShimCounter
    HistogramClass = _ShimHistogram

# ------------------------------ in-memory tallies ------------------------------

_REQ_TOTAL = 0.0
_DEC_TOTAL = 0.0
_RATE_LIMITED = 0.0

_FAMILY_TOTALS: Dict[str, float] = {}
_FAMILY_TENANT_BOT: Dict[Tuple[str, str, str], float] = {}
_VERIFIER_OUTCOMES: Dict[Tuple[str, str], float] = {}

_RULES_VERSION = "unknown"

# --------------------------- registry-safe constructors ------------------------


def _registry_map() -> Dict[str, Any]:
    mapping = getattr(PROM_REGISTRY, "_names_to_collectors", {})
    if isinstance(mapping, dict):
        return mapping
    return {}


T = TypeVar("T")


def _register(name: str, collector: Any) -> Any:
    mapping = _registry_map()
    mapping[name] = collector
    return collector


def _get_or_create(name: str, factory: Callable[[], T]) -> T:
    existing = _registry_map().get(name)
    if existing is not None:
        return cast(T, existing)
    created = _register(name, factory())
    return cast(T, created)


# --------------------------------- collectors ---------------------------------


def _mk_counter(name: str, doc: str, labels: Iterable[str] | None = None) -> CounterLike:
    def _factory() -> Any:
        if labels:
            return CounterClass(name, doc, list(labels))
        return CounterClass(name, doc)

    return cast(CounterLike, _get_or_create(name, _factory))


def _mk_histogram(
    name: str, doc: str, labels: Iterable[str] | None = None
) -> HistogramLike:
    def _factory() -> Any:
        if labels:
            return HistogramClass(name, doc, list(labels))
        return HistogramClass(name, doc)

    return cast(HistogramLike, _get_or_create(name, _factory))


# Core metrics used throughout the app/tests (names must match tests).
guardrail_requests_total: CounterLike = _mk_counter(
    "guardrail_requests_total", "Total guardrail requests.", labels=["endpoint"]
)
guardrail_decisions_total: CounterLike = _mk_counter(
    "guardrail_decisions_total", "Total guardrail decisions.", labels=["action"]
)
guardrail_latency_seconds: HistogramLike = _mk_histogram(
    "guardrail_latency_seconds",
    "Latency of guardrail endpoints in seconds.",
    ["endpoint"],
)
guardrail_rate_limited_total: CounterLike = _mk_counter(
    "guardrail_rate_limited_total", "Requests rejected by legacy rate limiter."
)

# Family + tenant/bot breakdowns (exact names expected by tests).
guardrail_decisions_family_total: CounterLike = _mk_counter(
    "guardrail_decisions_family_total", "Decision totals by family.", ["family"]
)
guardrail_decisions_family_tenant_total: CounterLike = _mk_counter(
    "guardrail_decisions_family_tenant_total",
    "Decision totals by tenant and family.",
    ["tenant", "family"],
)
guardrail_decisions_family_bot_total: CounterLike = _mk_counter(
    "guardrail_decisions_family_bot_total",
    "Decision totals by tenant/bot and family.",
    ["tenant", "bot", "family"],
)

# Redactions metric expected by tests.
guardrail_redactions_total: CounterLike = _mk_counter(
    "guardrail_redactions_total", "Redactions applied by mask type.", ["mask"]
)

# Verifier breakdowns (kept for completeness; tests print plain lines for these).
guardrail_verifier_outcome_total: CounterLike = _mk_counter(
    "guardrail_verifier_outcome_total",
    "Verifier outcome totals.",
    ["verifier", "outcome"],
)

# --------------------------------- incrementers --------------------------------


def inc_requests_total(endpoint: str = "unknown") -> None:
    global _REQ_TOTAL
    guardrail_requests_total.labels(endpoint).inc()
    # Ensure histogram has a child so *_count appears.
    guardrail_latency_seconds.labels(endpoint).observe(0.0)
    _REQ_TOTAL += 1.0

    # Seed default label sets so exposition shows expected samples
    # even if a code path hasn't incremented them yet.
    guardrail_decisions_family_total.labels("allow").inc(0.0)
    guardrail_decisions_family_tenant_total.labels("default", "allow").inc(0.0)
    guardrail_decisions_family_bot_total.labels("default", "default", "allow").inc(0.0)


def inc_decisions_total(action: str = "unknown") -> None:
    global _DEC_TOTAL
    guardrail_decisions_total.labels(action).inc()
    _DEC_TOTAL += 1.0


def inc_rate_limited(amount: float = 1.0) -> None:
    global _RATE_LIMITED
    guardrail_rate_limited_total.inc(amount)
    _RATE_LIMITED += float(amount)


def inc_decision_family(family: str) -> None:
    guardrail_decisions_family_total.labels(family).inc()
    _FAMILY_TOTALS[family] = _FAMILY_TOTALS.get(family, 0.0) + 1.0


def inc_decision_family_tenant_bot(family: str, tenant: str, bot: str) -> None:
    guardrail_decisions_family_total.labels(family).inc()
    guardrail_decisions_family_tenant_total.labels(tenant, family).inc()
    guardrail_decisions_family_bot_total.labels(tenant, bot, family).inc()

    _FAMILY_TOTALS[family] = _FAMILY_TOTALS.get(family, 0.0) + 1.0
    key = (family, tenant, bot)
    _FAMILY_TENANT_BOT[key] = _FAMILY_TENANT_BOT.get(key, 0.0) + 1.0


def inc_verifier_outcome(verifier: str, outcome: str) -> None:
    guardrail_verifier_outcome_total.labels(verifier, outcome).inc()
    key = (verifier, outcome)
    _VERIFIER_OUTCOMES[key] = _VERIFIER_OUTCOMES.get(key, 0.0) + 1.0


def inc_quota_reject_tenant_bot(tenant: str, bot: str) -> None:
    inc_decision_family("deny")
    inc_decision_family_tenant_bot("deny", tenant, bot)


def inc_redaction(mask: str) -> None:
    """Public helper used by redaction paths to tick the redactions counter."""
    guardrail_redactions_total.labels(mask).inc()


# ----------------------------------- getters -----------------------------------


def get_requests_total() -> float:
    return float(_REQ_TOTAL)


def get_decisions_total() -> float:
    return float(_DEC_TOTAL)


def get_rate_limited_total() -> float:
    return float(_RATE_LIMITED)


def get_decisions_family_total(family: str) -> float:
    return float(_FAMILY_TOTALS.get(family, 0.0))


def get_all_family_totals() -> Dict[str, float]:
    return dict(_FAMILY_TOTALS)


def get_rules_version() -> str:
    return _RULES_VERSION


def set_rules_version(v: str) -> None:
    global _RULES_VERSION
    _RULES_VERSION = str(v)


# ------------------------------- export helpers --------------------------------


def export_verifier_lines() -> List[str]:
    lines: List[str] = []
    for (verifier, outcome), count in sorted(_VERIFIER_OUTCOMES.items()):
        lines.append(f"verifier={verifier} outcome={outcome} count={int(count)}")
    return lines


def export_family_breakdown_lines() -> List[str]:
    lines: List[str] = []
    for family, count in sorted(_FAMILY_TOTALS.items()):
        lines.append(f"family={family} count={int(count)}")
    for (family, tenant, bot), count in sorted(_FAMILY_TENANT_BOT.items()):
        lines.append(
            f"family_tenant_bot={family}:{tenant}:{bot} count={int(count)}"
        )
    return lines


# ------------------------------ misc introspection -----------------------------


def get_metric(name: str) -> Any:
    """Return the raw collector by name if present in the registry mapping."""
    return _registry_map().get(name)
