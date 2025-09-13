"""Common HTTP header constants and helpers."""

from __future__ import annotations

from starlette.responses import Response

from app.services.policy import current_rules_version

TENANT_HEADER = "X-Tenant-ID"
BOT_HEADER = "X-Bot-ID"


def attach_guardrail_headers(
    response: Response,
    *,
    decision: str,
    ingress_action: str,
    egress_action: str,
) -> None:
    """Attach standard Guardrail headers to ``response``.

    Existing headers are preserved where possible; ``decision`` always overrides.
    """

    try:
        response.headers.setdefault(
            "X-Guardrail-Policy-Version", current_rules_version()
        )
    except Exception:  # pragma: no cover
        pass

    response.headers.setdefault("X-Guardrail-Ingress-Action", ingress_action)
    response.headers.setdefault("X-Guardrail-Egress-Action", egress_action)
    response.headers.setdefault("X-Guardrail-Decision", decision)

