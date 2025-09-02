# app/telemetry/metrics.py
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Tuple, Union

# Try to use real Prometheus. Fall back to light shims that match the surface we use.
try:
    from prometheus_client import Counter as PromCounter
    from prometheus_client import Histogram as PromHistogram
    from prometheus_client import REGISTRY as PROM_REGISTRY
    PROM_OK = True
except Exception:  # pragma: no cover - exercised implicitly in CI envs without prometheus
    PROM_OK = False

    class PromCounter:  # type: ignore[no-redef]
        """Minimal shim with Counter-like API (inc, labels)."""

        def __init__(self, *_: Any, **__: Any) -> None:
            self._value = 0.0
            self._children: Dict[Tuple[Any, ...], "PromCounter"] = {}

        def labels(self, *label_values: Any) -> "PromCounter":
            if label_values not in self._children:
                self._children[label_values] = PromCounter()
            return self._children[label_values]

        def inc(self, amount: float = 1.0) -> None:
            self._value += float(amount)

        # Helpers to inspect in tests/exports if needed.
        def _get(self) -> float:
            return self._value

        def _children_items(self) -> Iterable[Tuple[Tuple[Any, ...], "PromCounter"]]:
            return self._children.items()

    class PromHistogram:  # type: ignore[no-redef]
        """Minimal shim with Histogram-like API (observe, labels)."""

        def __init__(self, *_: Any, **__: Any) -> None:
            self._sum = 0.0
            self._count = 0
            self._children: Dict[Tuple[Any, ...], "PromHistogram"] = {}

        def labels(self, *label_values: Any) -> "PromHistogram":
            if label_values not in self._children:
                self._children[label_values] = PromHistogram()
            return self._children[label_values]

        def observe(self, value: float) -> None:
            self._sum += float(value)
            self._count += 1

        # Helpers for checks.
        def _snapshot(self) -> Tuple[float, int]:
            return self._sum, self._count

        def _children_items(self) -> Iterable[Tuple[Tuple[Any, ...], "PromHistogram"]]:
            return self._children.items()

    class _DummyRegistry:
        def __init__(self) -> None:
            self._names_to_collectors: Dict[str, Any] = {}

    PROM_REGISTRY = _DummyRegistry()  # type: ignore[no-redef]


# ------------------------------ in-memory tallies ------------------------------

# Keep simple mirrors so getters/exports work even if Prometheus is absent.
_REQ_TOTAL = 0.0
_DEC_TOTAL = 0.0
_RATE_LIMITED = 0.0

_FAMILY_TOTALS: Dict[str, float] = {}
_FAMILY_TENANT_BOT: Dict[Tuple[str, str, str], float] = {}
_VERIFIER_OUTCOMES: Dict[Tuple[str, str], float] = {}

_RULES_VERSION = "unknown"


# --------------------------- registry-safe constructors ------------------------

def _registry_map() -> Mapping[str, Any]:
    # CollectorRegistry in prometheus has a private mapping we can read.
    return getattr(PROM_REGISTRY, "_names_to_collectors", {})  # type: ignore[no-any-return]


def _register(name: str, collector: Any) -> Any:
    # Register only when the registry exposes the mapping (Prometheus or dummy).
    mapping = getattr(PROM_REGISTRY, "_names_to_collectors", None)
    if isinstance(mapping, dict):
        mapping[name] = collector
    return collector


def _get_or_create(name: str, factory: Any) -> Any:
    existing = _registry_map().get(name)
    if existing is not None:
        return existing
    # Create and register once per process.
    return _register(name, factory())


# --------------------------------- collectors ---------------------------------

def _mk_counter(name: str, doc: str, labels: Optional[Iterable[str]] = None) -> PromCounter:
    def _factory() -> PromCounter:
        if labels:
            return PromCounter(name, doc, list(labels))
        return PromCounter(name, doc)
    return _get_or_create(name, _factory)  # type: ignore[return-value]


def _mk_histogram(
    name: str,
    doc: str,
    labels: Optional[Iterable[str]] = None,
) -> PromHistogram:
    def _factory() -> PromHistogram:
        if labels:
            return PromHistogram(name, doc, list(labels))
        return PromHistogram(name, doc)
    return _get_or_create(name, _factory)  # type: ignore[return-value]


# Core metrics used throughout the app/tests.
guardrail_requests_total: PromCounter = _mk_counter(
    "guardrail_requests_total",
    "Total guardrail requests.",
    labels=["endpoint"],
)

guardrail_decisions_total: PromCounter = _mk_counter(
    "guardrail_decisions_total",
    "Total guardrail decisions.",
    labels=["action"],
)

guardrail_latency_seconds: PromHistogram = _mk_histogram(
    "guardrail_latency_seconds",
    "Guardrail endpoint latency in seconds.",
    labels=["endpoint"],
)

guardrail_rate_limited_total: PromCounter = _mk_counter(
    "guardrail_rate_limited_total",
    "Requests rejected by legacy rate limiter.",
)

# Decision family totals: by family (allow/deny/redact/etc.).
guardrail_family_total: PromCounter = _mk_counter(
    "guardrail_family_total",
    "Decision totals by family.",
    labels=["family"],
)

# Decision family + tenant + bot breakdown.
guardrail_family_tenant_bot_total: PromCounter = _mk_counter(
    "guardrail_family_tenant_bot_total",
    "Decision totals by family and tenant/bot.",
    labels=["family", "tenant", "bot"],
)

# Per-verifier outcomes.
guardrail_verifier_outcome_total: PromCounter = _mk_counter(
    "guardrail_verifier_outcome_total",
    "Verifier outcome totals.",
    labels=["verifier", "outcome"],
)


# --------------------------------- incrementers --------------------------------

def inc_requests_total(endpoint: str) -> None:
    global _REQ_TOTAL
    guardrail_requests_total.labels(endpoint).inc()
    _REQ_TOTAL += 1.0


def inc_decisions_total(action: str) -> None:
    global _DEC_TOTAL
    guardrail_decisions_total.labels(action).inc()
    _DEC_TOTAL += 1.0


def inc_rate_limited() -> None:
    global _RATE_LIMITED
    guardrail_rate_limited_total.inc()
    _RATE_LIMITED += 1.0


def inc_decision_family(family: str) -> None:
    guardrail_family_total.labels(family).inc()
    _FAMILY_TOTALS[family] = _FAMILY_TOTALS.get(family, 0.0) + 1.0


def inc_decision_family_tenant_bot(family: str, tenant: str, bot: str) -> None:
    guardrail_family_tenant_bot_total.labels(family, tenant, bot).inc()
    key = (family, tenant, bot)
    _FAMILY_TENANT_BOT[key] = _FAMILY_TENANT_BOT.get(key, 0.0) + 1.0


def inc_verifier_outcome(verifier: str, outcome: str) -> None:
    guardrail_verifier_outcome_total.labels(verifier, outcome).inc()
    key = (verifier, outcome)
    _VERIFIER_OUTCOMES[key] = _VERIFIER_OUTCOMES.get(key, 0.0) + 1.0


def inc_quota_reject_tenant_bot(tenant: str, bot: str) -> None:
    # Some tests call this; count it as a family "deny" and a tenant/bot increment.
    inc_decision_family("deny")
    inc_decision_family_tenant_bot("deny", tenant, bot)


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
    """
    Provide a stable, textual dump for /metrics helper route.
    Shape is intentionally simple for tests.
    """
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
            "family_tenant_bot="
            f"{family}:{tenant}:{bot} count={int(count)}"
        )
    return lines


# ------------------------------ misc introspection -----------------------------

def get_metric(name: str) -> Any:
    """
    Return the raw collector by name if registered in the registry mapping.
    Safe to call with either real or dummy registry.
    """
    return _registry_map().get(name)
