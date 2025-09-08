from __future__ import annotations

from typing import Any, Callable, Dict, Iterable, List, Protocol, Tuple, TypeVar, cast

# ---- Protocols (surface we rely on) ------------------------------------------


class CounterLike(Protocol):
    def labels(self, *label_values: Any) -> "CounterLike": ...
    def inc(self, amount: float = 1.0) -> None: ...


class HistogramLike(Protocol):
    def labels(self, *label_values: Any) -> "HistogramLike": ...
    def observe(self, value: float) -> None: ...


# ---- Prometheus or shims -----------------------------------------------------

PROM_REGISTRY: Any
CounterClass: Any
HistogramClass: Any

try:
    from prometheus_client import REGISTRY as _PREG, Counter as _PCounter, Histogram as _PHistogram

    PROM_REGISTRY = _PREG
    CounterClass = _PCounter
    HistogramClass = _PHistogram
    _PROM_OK = True
except Exception:  # pragma: no cover
    _PROM_OK = False

    class _ShimCounter:
        def __init__(self, *_: Any, **__: Any) -> None:
            self._value = 0.0
            self._children: Dict[Tuple[Any, ...], "_ShimCounter"] = {}

        def labels(self, *label_values: Any) -> "_ShimCounter":
            key = tuple(label_values)
            if key not in self._children:
                self._children[key] = _ShimCounter()
            return self._children[key]

        def inc(self, amount: float = 1.0) -> None:
            self._value += float(amount)

    class _ShimHistogram:
        def __init__(self, *_: Any, **__: Any) -> None:
            self._sum = 0.0
            self._count = 0
            self._children: Dict[Tuple[Any, ...], "_ShimHistogram"] = {}

        def labels(self, *label_values: Any) -> "_ShimHistogram":
            key = tuple(label_values)
            if key not in self._children:
                self._children[key] = _ShimHistogram()
            return self._children[key]

        def observe(self, value: float) -> None:
            self._sum += float(value)
            self._count += 1

    class _DummyRegistry:
        def __init__(self) -> None:
            self._names_to_collectors: Dict[str, Any] = {}

    PROM_REGISTRY = _DummyRegistry()
    CounterClass = _ShimCounter
    HistogramClass = _ShimHistogram


# ---- Minimal helpers for registry access -------------------------------------


def _registry_map() -> Dict[str, Any]:
    mapping = getattr(PROM_REGISTRY, "_names_to_collectors", {})
    return mapping if isinstance(mapping, dict) else {}


T = TypeVar("T")


def _get_or_create(name: str, factory: Callable[[], T]) -> T:
    existing = _registry_map().get(name)
    if existing is not None:
        return cast(T, existing)
    created = factory()
    # best-effort: mirror how prometheus_client tracks collectors
    _registry_map()[name] = created
    return cast(T, created)


# ---- Collector factories ------------------------------------------------------


def _mk_counter(name: str, doc: str, labels: Iterable[str] | None = None) -> CounterLike:
    def _factory() -> Any:
        if labels:
            return CounterClass(name, doc, list(labels))
        return CounterClass(name, doc)

    return cast(CounterLike, _get_or_create(name, _factory))


def _mk_histogram(name: str, doc: str, labels: Iterable[str] | None = None) -> HistogramLike:
    def _factory() -> Any:
        if labels:
            return HistogramClass(name, doc, list(labels))
        return HistogramClass(name, doc)

    return cast(HistogramLike, _get_or_create(name, _factory))


# ---- Core collectors (names must match tests) --------------------------------

guardrail_requests_total: CounterLike = _mk_counter(
    "guardrail_requests_total", "Total guardrail requests.", labels=["endpoint"]
)
guardrail_decisions_total: CounterLike = _mk_counter(
    "guardrail_decisions_total", "Total guardrail decisions.", labels=["action"]
)
guardrail_latency_seconds: HistogramLike = _mk_histogram(
    "guardrail_latency_seconds", "Latency in seconds.", labels=["endpoint"]
)
guardrail_rate_limited_total: CounterLike = _mk_counter(
    "guardrail_rate_limited_total", "Requests rejected by legacy rate limiter."
)
guardrail_quota_rejects_total: CounterLike = _mk_counter(
    "guardrail_quota_rejects_total", "Requests rejected due to quotas.", ["tenant", "bot"]
)

# Family + tenant/bot breakdowns
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

# Directional redactions (direction, mask)
guardrail_redactions_total: CounterLike = _mk_counter(
    "guardrail_redactions_total", "Redactions by direction and mask.", ["direction", "mask"]
)

# Direction-scoped decision families
guardrail_ingress_decisions_family_total: CounterLike = _mk_counter(
    "guardrail_ingress_decisions_family_total", "Ingress decisions by family.", ["family"]
)
guardrail_egress_decisions_family_total: CounterLike = _mk_counter(
    "guardrail_egress_decisions_family_total", "Egress decisions by family.", ["family"]
)

# Verifier outcomes
guardrail_verifier_outcome_total: CounterLike = _mk_counter(
    "guardrail_verifier_outcome_total", "Verifier outcome totals.", ["verifier", "outcome"]
)

# OCR observability (optional, lightweight)
guardrail_ocr_extractions_total: CounterLike = _mk_counter(
    "guardrail_ocr_extractions_total",
    "OCR extractions by type and outcome.",
    ["type", "outcome"],
)
guardrail_ocr_bytes_total: CounterLike = _mk_counter(
    "guardrail_ocr_bytes_total",
    "Total bytes processed by OCR input type.",
    ["type"],
)

# ---- In-memory tallies used for the plaintext export lines -------------------

_REQ_TOTAL = 0.0
_DEC_TOTAL = 0.0
_RATE_LIMITED = 0.0

# Global family -> count
_FAMILY_TOTALS: Dict[str, float] = {}

# (family, tenant, bot) -> count
_FAMILY_TENANT_BOT: Dict[Tuple[str, str, str], float] = {}

_RULES_VERSION = "unknown"


# ---- Incrementers ------------------------------------------------------------


def inc_requests_total(endpoint: str = "unknown") -> None:
    """
    Bumps request counter and ensures histogram child exists so *_count appears.
    Also seeds default family label samples so the exposition is stable.
    """
    global _REQ_TOTAL
    guardrail_requests_total.labels(endpoint).inc()
    guardrail_latency_seconds.labels(endpoint).observe(0.0)
    _REQ_TOTAL += 1.0

    # Seed common label combos at 0 so tests can find them even before increments.
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


def inc_ingress_family(family: str) -> None:
    """Increment ingress-scoped decision family counter and global family."""
    guardrail_ingress_decisions_family_total.labels(family).inc()
    inc_decision_family(family)


def inc_egress_family(family: str) -> None:
    """Increment egress-scoped decision family counter and global family."""
    guardrail_egress_decisions_family_total.labels(family).inc()
    inc_decision_family(family)


def inc_decision_family_tenant_bot(family: str, tenant: str, bot: str) -> None:
    guardrail_decisions_family_total.labels(family).inc()
    guardrail_decisions_family_tenant_total.labels(tenant, family).inc()
    guardrail_decisions_family_bot_total.labels(tenant, bot, family).inc()

    _FAMILY_TOTALS[family] = _FAMILY_TOTALS.get(family, 0.0) + 1.0
    key = (family, tenant, bot)
    _FAMILY_TENANT_BOT[key] = _FAMILY_TENANT_BOT.get(key, 0.0) + 1.0


def inc_verifier_outcome(verifier: str, outcome: str) -> None:
    guardrail_verifier_outcome_total.labels(verifier, outcome).inc()


def inc_quota_reject_tenant_bot(tenant: str, bot: str) -> None:
    # Quota rejects count as deny
    inc_decision_family("deny")
    inc_decision_family_tenant_bot("deny", tenant, bot)
    guardrail_quota_rejects_total.labels(tenant, bot).inc()


def inc_redaction(mask: str, direction: str = "unknown", amount: float = 1.0) -> None:
    """
    Increment redaction counters with direction + mask.
    `amount` lets callers record multiple substitutions in one go.
    """
    guardrail_redactions_total.labels(direction, mask).inc(amount)


def inc_ocr_extraction(typ: str, outcome: str) -> None:
    guardrail_ocr_extractions_total.labels(typ, outcome).inc()


def add_ocr_bytes(typ: str, nbytes: int | float) -> None:
    try:
        v = float(nbytes)
    except Exception:
        v = 0.0
    guardrail_ocr_bytes_total.labels(typ).inc(v)


# ---- Getters -----------------------------------------------------------------


def get_requests_total() -> float:
    return float(_REQ_TOTAL)


def get_decisions_total() -> float:
    return float(_DEC_TOTAL)


def get_rate_limited_total() -> float:
    return float(_RATE_LIMITED)


def get_all_family_totals() -> Dict[str, float]:
    return dict(_FAMILY_TOTALS)


def get_rules_version() -> str:
    return _RULES_VERSION


def set_rules_version(v: str) -> None:
    global _RULES_VERSION
    _RULES_VERSION = str(v)


def get_decisions_family_total(family: str) -> float:
    """Return the total decisions for a given family label."""
    return float(_FAMILY_TOTALS.get(family, 0.0))


# ---- Text export helpers used by /metrics ------------------------------------


def export_verifier_lines() -> List[str]:
    """
    Emit Prometheus-style plaintext for guardrail_verifier_outcome_total.

    Works with both the real ``prometheus_client`` and the in-process shim.
    """
    name = "guardrail_verifier_outcome_total"
    coll = get_metric(name)
    if coll is None:
        return []

    lines: List[str] = []
    lines.append("# HELP guardrail_verifier_outcome_total Verifier outcome totals.")
    lines.append("# TYPE guardrail_verifier_outcome_total counter")
    try:
        if _PROM_OK and hasattr(coll, "collect"):
            # Use the collector's samples from prometheus_client.
            for mf in coll.collect():  # type: ignore[attr-defined]
                for s in getattr(mf, "samples", []):
                    # Only the *_total sample contains the counter value.
                    if not str(s.name).endswith("_total"):
                        continue
                    labels = dict(getattr(s, "labels", {}) or {})
                    verifier = str(labels.get("verifier", ""))
                    outcome = str(labels.get("outcome", ""))
                    value = float(getattr(s, "value", 0.0))
                    lines.append(
                        f'{name}{{verifier="{verifier}",outcome="{outcome}"}} {value}'
                    )
        else:
            # Shim path: walk child counters.
            children = getattr(coll, "_children", {})  # type: ignore[attr-defined]
            for key, child in sorted(children.items()):
                verifier = str(key[0]) if len(key) > 0 else ""
                outcome = str(key[1]) if len(key) > 1 else ""
                value = float(getattr(child, "_value", 0.0))
                lines.append(
                    f'{name}{{verifier="{verifier}",outcome="{outcome}"}} {value}'
                )
    except Exception:
        # Best-effort only.
        return []

    return lines


def _aggregate_tenant_totals() -> Dict[Tuple[str, str], float]:
    """
    Returns a mapping of (tenant, family) -> count, derived from
    the (family, tenant, bot) tallies.
    """
    agg: Dict[Tuple[str, str], float] = {}
    for (family, tenant, _bot), cnt in _FAMILY_TENANT_BOT.items():
        key = (tenant, family)
        agg[key] = agg.get(key, 0.0) + float(cnt)
    return agg


def export_family_breakdown_lines() -> List[str]:
    """
    Emit Prometheus-style lines for tenant/bot breakdowns so tests can
    grep for:
      guardrail_decisions_family_tenant_total{tenant="T",family="F"} N
      guardrail_decisions_family_bot_total{tenant="T",bot="B",family="F"} N
    """
    lines: List[str] = []

    # Tenant-level totals
    tenant_agg = _aggregate_tenant_totals()
    if tenant_agg:
        lines.append(
            "# HELP guardrail_decisions_family_tenant_total "
            "Decision totals by tenant and family."
        )
        lines.append("# TYPE guardrail_decisions_family_tenant_total counter")
        for (tenant, family), v in sorted(tenant_agg.items()):
            lines.append(
                'guardrail_decisions_family_tenant_total{tenant="%s",family="%s"} %s'
                % (tenant, family, float(v))
            )

    # Tenant/bot-level totals
    if _FAMILY_TENANT_BOT:
        lines.append(
            "# HELP guardrail_decisions_family_bot_total "
            "Decision totals by tenant/bot and family."
        )
        lines.append("# TYPE guardrail_decisions_family_bot_total counter")
        for (family, tenant, bot), v in sorted(_FAMILY_TENANT_BOT.items()):
            lines.append(
                'guardrail_decisions_family_bot_total{tenant="%s",bot="%s",family="%s"} %s'
                % (tenant, bot, family, float(v))
            )

    return lines


# ---- Introspection -----------------------------------------------------------


def get_metric(name: str) -> Any:
    return _registry_map().get(name)

# --- PDF hidden-text telemetry ------------------------------------------------
# Placed here to avoid touching existing counters and keep diff minimal.

# Global counters for PDF hidden-text detections.
guardrail_pdf_hidden_total: CounterLike = _mk_counter(
    "guardrail_pdf_hidden_total",
    "Hidden text detections in PDFs.",
    labels=["reason"],
)
guardrail_pdf_hidden_bytes_total: CounterLike = _mk_counter(
    "guardrail_pdf_hidden_bytes_total",
    "Total bytes of PDFs flagged for hidden text.",
)

def inc_pdf_hidden(reason: str) -> None:
    """Increment hidden-text detection counter for the given reason."""
    guardrail_pdf_hidden_total.labels(str(reason or "unknown")).inc()


def add_pdf_hidden_bytes(n: int) -> None:
    """Accumulate total bytes of PDFs where hidden text was detected."""
    try:
        v = float(n)
    except Exception:
        v = 0.0
    guardrail_pdf_hidden_bytes_total.inc(v)
