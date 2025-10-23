from __future__ import annotations

import re
from typing import Final

_UUID_RE: Final = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
_HEX_RE: Final = re.compile(r"^[0-9a-fA-F]{8,}$")
_NUM_RE: Final = re.compile(r"^[0-9]{4,}$")
_ULID_RE: Final = re.compile(r"^[0-9A-HJKMNP-TV-Z]{26}$")

_ALLOWED: Final[frozenset[str]] = frozenset(
    {
        "/",
        "/.well-known/security.txt",
        "/admin",
        "/admin/active-policy",
        "/admin/adjudications",
        "/admin/adjudications.ndjson",
        "/admin/api/adjudications",
        "/admin/api/adjudications/export.ndjson",
        "/admin/api/audit/export.ndjson",
        "/admin/api/audit/recent",
        "/admin/api/data/delete",
        "/admin/api/data/export.ndjson",
        "/admin/api/decisions",
        "/admin/api/decisions/export",
        "/admin/api/decisions/export.csv",
        "/admin/api/decisions/export.ndjson",
        "/admin/api/egress/incidents",
        "/admin/api/features",
        "/admin/api/me",
        "/admin/api/metrics/mitigation-overrides",
        "/admin/api/mitigation-mode",
        "/admin/api/mitigation-modes",
        "/admin/api/mitigation/modes",
        "/admin/api/policy/diff",
        "/admin/api/policy/packs",
        "/admin/api/policy/reload",
        "/admin/api/policy/validate",
        "/admin/api/policy/version",
        "/admin/api/retention/execute",
        "/admin/api/retention/preview",
        "/admin/api/scope/bindings",
        "/admin/api/scope/effective",
        "/admin/api/scope/secrets",
        "/admin/api/secrets/strict",
        "/admin/api/tokens",
        "/admin/api/tokens/mint",
        "/admin/api/tokens/revoke",
        "/admin/api/verifier/router/snapshot",
        "/admin/api/webhooks/dlq",
        "/admin/api/webhooks/dlq/purge",
        "/admin/api/webhooks/dlq/retry",
        "/admin/api/webhooks/replay",
        "/admin/api/webhooks/status",
        "/admin/audit/export",
        "/admin/auth/callback",
        "/admin/auth/login",
        "/admin/auth/logout",
        "/admin/bindings",
        "/admin/bindings/apply",
        "/admin/bindings/apply_demo_defaults",
        "/admin/bindings/apply_golden",
        "/admin/bindings/apply_strict_secrets",
        "/admin/bindings/resolve",
        "/admin/bindings/ui",
        "/admin/compliance/hash",
        "/admin/compliance/status",
        "/admin/config",
        "/admin/config/rollback",
        "/admin/config/versions",
        "/admin/decisions",
        "/admin/decisions.ndjson",
        "/admin/decisions/:id/details",
        "/admin/decisions/export.csv",
        "/admin/decisions/stream",
        "/admin/echo",
        "/admin/flags",
        "/admin/idempotency/:id",
        "/admin/idempotency/recent",
        "/admin/metrics",
        "/admin/mitigation_modes",
        "/admin/policies/active",
        "/admin/policies/preview",
        "/admin/policy",
        "/admin/policy/current",
        "/admin/policy/packs",
        "/admin/policy/reload",
        "/admin/quota/reset",
        "/admin/quota/status",
        "/admin/retention/plan",
        "/admin/retention/policies",
        "/admin/retention/purge",
        "/admin/retention/receipts",
        "/admin/retention/receipts/:id",
        "/admin/retention/verify/:id",
        "/admin/rulepacks",
        "/admin/rulepacks/:id",
        "/admin/snapshot",
        "/admin/threat/reload",
        "/admin/ui",
        "/admin/ui/adjudications",
        "/admin/ui/bindings",
        "/admin/ui/bindings/apply_demo_defaults",
        "/admin/ui/bindings/apply_golden",
        "/admin/ui/bindings/apply_strict_secrets",
        "/admin/ui/bindings/data",
        "/admin/ui/config",
        "/admin/ui/config/history",
        "/admin/ui/decisions",
        "/admin/ui/export/decisions",
        "/admin/ui/reload",
        "/admin/ui/webhooks",
        "/admin/webhook/config",
        "/admin/webhook/test",
        "/admin/webhooks",
        "/admin/webhooks/dlq/:id",
        "/admin/webhooks/dlq/:id/replay",
        "/admin/webhooks/dlq/peek",
        "/admin/webhooks/dlq/pending",
        "/admin/webhooks/dlq/purge",
        "/admin/webhooks/dlq/quarantine",
        "/admin/webhooks/dlq/replay",
        "/demo/egress_stream",
        "/docs",
        "/docs/oauth2-redirect",
        "/guardrail",
        "/guardrail/",
        "/guardrail/batch_evaluate",
        "/guardrail/egress_batch",
        "/guardrail/egress_evaluate",
        "/guardrail/evaluate",
        "/guardrail/evaluate_multipart",
        "/guardrail/output",
        "/health",
        "/healthz",
        "/live",
        "/livez",
        "/metrics",
        "/openai/deployments/:id/chat/completions",
        "/openai/deployments/:id/embeddings",
        "/openapi.json",
        "/policy/version",
        "/proxy/chat",
        "/ready",
        "/readyz",
        "/redoc",
        "/robots.txt",
        "/stream/demo",
        "/v1/batch/batch_evaluate",
        "/v1/batch/egress_batch",
        "/v1/chat/completions",
        "/v1/completions",
        "/v1/embeddings",
        "/v1/guardrail",
        "/v1/guardrail/",
        "/v1/guardrail/egress_evaluate",
        "/v1/guardrail/evaluate",
        "/v1/guardrail/evaluate_multipart",
        "/v1/health",
        "/v1/images/edits",
        "/v1/images/generations",
        "/v1/images/variations",
        "/v1/models",
        "/v1/moderations",
        "/verifier/test",
        "/version",
    }
)


def _normalize_path(path: str) -> str:
    segs: list[str] = []
    for segment in path.split("/"):
        if not segment:
            continue
        if _UUID_RE.match(segment) or _ULID_RE.match(segment):
            segs.append(":id")
        elif len(segment) > 32:
            segs.append(":seg")
        elif _NUM_RE.match(segment) or _HEX_RE.match(segment):
            segs.append(":id")
        else:
            segs.append(segment)
    return "/" + "/".join(segs) if segs else "/"


def route_label(path: str) -> str:
    """
    Clamp a raw URL path to a safe Prometheus label.
    - Return an allowlisted static path as-is.
    - Otherwise, normalize dynamic segments (UUID/ULID/hex/nums) to templates,
      and only return the normalized label if it is explicitly allowlisted.
    - Fallback to 'other' for everything else to avoid high-cardinality series.
    """

    if not path:
        return "other"
    trimmed = path.split("?", 1)[0]
    if trimmed in _ALLOWED:
        return trimmed
    normalized = _normalize_path(trimmed)
    return normalized if normalized in _ALLOWED else "other"
