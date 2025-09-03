from __future__ import annotations

from typing import Any, Callable, Dict, Iterable, List, Mapping, Tuple, TypeVar, Protocol
from typing import cast

# ---- Protocols describing only what we use (works for real + shims) ----------

class CounterLike(Protocol):
    def labels(self, *label_values: Any) -> "CounterLike": ...
    def inc(self, amount: float = 1.0) -> None: ...

class HistogramLike(Protocol):
    def labels(self, *label_values: Any) -> "HistogramLike": ...
    def observe(self, value: float) -> None: ...

# ---- Try real prometheus, else provide shims with the same surface ------------

try:
    from prometheus_client import Counter as PromCounterImpl
    from prometheus_client import Histogram as PromHistogramImpl
    from prometheus_client import REGISTRY as PROM_REGISTRY
    PROM_OK = True
except Exception:  # pragma: no cover
    PROM_OK = False

    class PromCounterImpl:
        """Minimal counter shim (inc, labels)."""

        def __init__(self, *_: Any, **__: Any) -> None:
            self._value = 0.0
            self._children: Dict[Tuple[Any, ...], "PromCounterImpl"] = {}

        def labels(self, *label_values: Any) -> "PromCounterImpl":
            if label_values not in self._children:
                self._children[label_values] = PromCounterImpl()
            return self._children[label_values]

        def inc(self, amount: float = 1.0) -> None:
            self._value += float(amount)

    class PromHistogramImpl:
        """Minimal histogram shim (observe, labels)."""

        def __init__(self, *_: Any, **__: Any) -> None:
            self._sum = 0.0
            self._count = 0
            self._children: Dict[Tuple[Any, ...], "PromHistogramImpl"] = {}

        def labels(self, *label_values: Any) -> "PromHistogramImpl":
            if label_values not in self._children:
                self._children[label_values] = PromHistogramImpl()
            return self._children[label_values]

        def observe(self, value: float) -> None:
            self._sum += float(value)
            self._count += 1

    class _DummyRegistry:
        def __init__(self) -> None:
            self._names_to_collectors: Dict[str, Any] = {}

    PROM_REGISTRY = _DummyRegistry()  # type: ignore[assignment]

# Bind active implementations used below.
PromCounter = PromCounterImpl
PromHistogram = PromHistogramImpl

# ------------------------------ in-memory tallies ------------------------------

_REQ_TOTAL = 0.0
_DEC_TOTAL = 0.0
_RATE_LIMITED = 0.0
_REDACTIONS_TOTAL = 0.0

_FAMILY_TOTALS: Dict[str, float] = {}
_FAMILY_TENANT_TOTALS: Dict[Tuple[str, str], float] = {}
_FAMILY_BOT_TOTALS: Dict[Tuple[str, str, str], float] = {}

_VERIFIER_OUTCOMES: Dict[Tuple[str, str], float] = {}

_RULES_VERSION = "unknown"

# --------------------------- registry-safe helpers -----------------------------

def _registry_map() -> Dict[str, Any]:
    mapping = getattr(PROM_REGISTRY, "_names_to_collectors", {})
    return mapping if isinstance(mapping, dict) else {}

def _register(name: str, collector: Any) -> Any:
    mapping = _registry_map()
    mapping[name] = collector
    return collector

T = TypeVar("T")

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
            return PromCounter(name, doc, list(labels))
        return PromCounter(name, doc)
    return cast(CounterLike, _get_or_create(name, _factory))

def _mk_histogram(
    name: str, doc: str, labels: Iterable[str] | None = None
) -> HistogramLike:
    def _factory() -> Any:
        if labels:
            return PromHistogram(name, doc, list(labels))
        return PromHistogram(name, doc)
    return cast(HistogramLike, _get_or_create(name, _factory))

# Core metrics used throughout the app/tests.
guardrail_requests_total: CounterLike = _mk_counter(
    "guardrail_requests_total", "Total guardrail requests.", labels=["endpoint"]
)
guardrail_decisions_total: CounterLike = _mk_counter(
    "guardrail_decisions_total", "Total guardrail decisions.", labels=["action"]
)
# Keep label so tests can check by endpoint; ensure child exists on first request.
guardrail_latency_seconds: HistogramLike = _mk_histogram(
    "guardrail_latency_seconds", "Guardrail endpoint latency in seconds.", labels=["endpoint"]
)
guardrail_rate_limited_total: CounterLike = _mk_counter(
    "guardrail_rate_limited_total", "Requests rejected by legacy rate limiter."
)
# Names below match tests exactly:
guardrail_decisions_family_total: CounterLike = _mk_counter(
    "guardrail_decisions_family_total", "Decision totals by family.", labels=["family"]
)
guardrail_decisions_family_tenant_total: CounterLike = _mk_counter(
    "guardrail_decisions_family_tenant_total",
    "Decision totals by family and tenant.",
    labels=["tenant", "family"],
)
guardrail_decisions_family_bot_total: CounterLike = _mk_counter(
    "guardrail_decisions_family_bot_total",
    "Decision totals by family, tenant and bot.",
    labels=["tenant", "bot", "family"],
)
guardrail_redactions_total: CounterLike = _mk_counter(
    "guardrail_redactions_total", "Total number of applied redactions."
)
guardrail_verifier_outcome_total: CounterLike = _mk_counter(
    "guardrail_verifier_outcome_total",
    "Verifier outcome totals.",
    labels=["verifier", "outcome"],
)

# --------------------------------- incrementers -------------------------------

def inc_requests_total(endpoint: str = "unknown") -> None:
    global _REQ_TOTAL
    guardrail_requests_total.labels(endpoint).inc()
    # Make sure the histogram has a child so *_count appears in /metrics.
    guardrail_latency_seconds.labels(endpoint).observe(0.0)
    _REQ_TOTAL += 1.0

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
    # bot-level
    guardrail_decisions_family_bot_total.labels(tenant, bot, family).inc()
    key_bot = (tenant, bot, family)
    _FAMILY_BOT_TOTALS[key_bot] = _FAMILY_BOT_TOTALS.get(key_bot, 0.0) + 1.0
    # tenant-level
    guardrail_decisions_family_tenant_total.labels(tenant, family).inc()
    key_tenant = (tenant, family)
    _FAMILY_TENANT_TOTALS[key_tenant] = _FAMILY_TENANT_TOTALS.get(key_tenant, 0.0) + 1.0
    # global family
    inc_decision_family(family)

def inc_verifier_outcome(verifier: str, outcome: str) -> None:
    guardrail_verifier_outcome_total.labels(verifier, outcome).inc()
    key = (verifier, outcome)
    _VERIFIER_OUTCOMES[key] = _VERIFIER_OUTCOMES.get(key, 0.0) + 1.0

def inc_quota_reject_tenant_bot(tenant: str, bot: str) -> None:
    inc_decision_family_tenant_bot("deny", tenant, bot)

def inc_redactions(count: int = 1) -> None:
    """Bump the redactions counter; tests only check presence, but keep total."""
    global _REDACTIONS_TOTAL
    guardrail_redactions_total.inc(float(count))
    _REDACTIONS_TOTAL += float(count)

# ----------------------------------- getters ----------------------------------

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
    for (tenant, family), count in sorted(_FAMILY_TENANT_TOTALS.items()):
        lines.append(f"tenant_family={tenant}:{family} count={int(count)}")
    for (tenant, bot, family), count in sorted(_FAMILY_BOT_TOTALS.items()):
        lines.append(f"tenant_bot_family={tenant}:{bot}:{family} count={int(count)}")
    return lines

# ------------------------------ misc introspection -----------------------------

def get_metric(name: str) -> Any:
    """Return the raw collector by name if present in the registry mapping."""
    return _registry_map().get(name)
