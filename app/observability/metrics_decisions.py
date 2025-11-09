from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any, Dict, Optional

if TYPE_CHECKING:  # pragma: no cover
    from prometheus_client import Counter as PromCounter
else:  # pragma: no cover
    PromCounter = Any

try:  # pragma: no cover
    from prometheus_client import Counter as _imported_counter
except Exception:  # pragma: no cover
    _COUNTER_FACTORY: Optional[Any] = None
else:  # pragma: no cover
    _COUNTER_FACTORY = _imported_counter

_METRICS_ENABLED = os.getenv("METRICS_ENABLED", "true").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)
# Keep cardinality sane by default; tenant/bot labels are off unless opted-in.
_TB_LABELS = os.getenv("METRICS_DECISION_TENANT_BOT_LABELS", "false").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)

# Label set: outcome is always included; rule_id only for redact; tenant/bot optional
_labels = ["outcome"]
if _TB_LABELS:
    _labels += ["tenant", "bot"]
# We'll allow rule_id as a separate counter to avoid mixing label schemas
_rule_labels = _labels + (["rule_id"] if "rule_id" not in _labels else [])

# Lazy singletons
_COUNTER: Optional[PromCounter] = None
_COUNTER_REDACT: Optional[PromCounter] = None


def _get_counter():
    global _COUNTER
    if not _METRICS_ENABLED or _COUNTER_FACTORY is None:
        return None
    if _COUNTER is None:
        try:
            _COUNTER = _COUNTER_FACTORY(
                "guardrail_decisions_total",
                "Count of guardrail decisions by outcome",
                _labels,
            )
        except ValueError:
            try:
                from prometheus_client import REGISTRY

                existing = getattr(REGISTRY, "_names_to_collectors", {})
                _COUNTER = existing.get("guardrail_decisions_total")
            except Exception:
                _COUNTER = None
    return _COUNTER


def _get_counter_redact():
    global _COUNTER_REDACT
    if not _METRICS_ENABLED or _COUNTER_FACTORY is None:
        return None
    if _COUNTER_REDACT is None:
        try:
            _COUNTER_REDACT = _COUNTER_FACTORY(
                "guardrail_redact_decisions_total",
                "Count of redact outcomes, with rule_id",
                _rule_labels,
            )
        except ValueError:
            try:
                from prometheus_client import REGISTRY

                existing = getattr(REGISTRY, "_names_to_collectors", {})
                _COUNTER_REDACT = existing.get("guardrail_redact_decisions_total")
            except Exception:
                _COUNTER_REDACT = None
    return _COUNTER_REDACT


def inc(outcome: str, tenant: Optional[str] = None, bot: Optional[str] = None) -> None:
    c = _get_counter()
    if c is None:
        return
    labels: Dict[str, str] = {"outcome": outcome}
    if _TB_LABELS:
        labels["tenant"] = tenant or "unknown"
        labels["bot"] = bot or "unknown"
    try:
        c.labels(**labels).inc()
    except Exception:
        pass


def inc_redact(rule_id: str, tenant: Optional[str] = None, bot: Optional[str] = None) -> None:
    c = _get_counter_redact()
    if c is None:
        return
    labels: Dict[str, str] = {"outcome": "redact"}
    if _TB_LABELS:
        labels["tenant"] = tenant or "unknown"
        labels["bot"] = bot or "unknown"
    labels["rule_id"] = rule_id or "unknown"
    try:
        c.labels(**labels).inc()
    except Exception:
        pass
