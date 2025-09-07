from __future__ import annotations

from typing import Final

# Fixed allow-list to prevent high-cardinality label explosions in Prometheus.
# Any path not present maps to "other".
_ALLOWED: Final[set[str]] = {
    "/",
    "/health",
    "/metrics",
    "/guardrail",
    "/guardrail/",
    "/guardrail/evaluate",
    "/guardrail/egress_evaluate",
    "/guardrail/batch_evaluate",
    "/guardrail/evaluate_multipart",
    "/guardrail/output",
    "/admin/policy/reload",
    "/admin/threat/reload",
    "/proxy/chat",
    "/v1/chat/completions",
}


def route_label(path: str) -> str:
    """
    Clamp a raw URL path to a safe label. Unknown/dynamic paths collapse to "other".
    """
    if not path:
        return "other"
    p = path.split("?", 1)[0]
    return p if p in _ALLOWED else "other"
