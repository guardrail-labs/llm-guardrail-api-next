from __future__ import annotations

from typing import List

from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST, REGISTRY, generate_latest

from app.telemetry import metrics as tmetrics

router = APIRouter(tags=["metrics"])


def _safe_guardrail_legacy_totals() -> List[str]:
    """
    Pull optional legacy counters from guardrail routes if available.
    Returns Prometheus text lines or an empty list.
    """
    out: List[str] = []
    try:
        # Import lazily to avoid a hard dependency if the file moves or is omitted.
        from app.routes.guardrail import (
            get_requests_total,
            get_decisions_total,
        )

        req = float(get_requests_total())
        dec = float(get_decisions_total())
        out.append(
            "# HELP guardrail_requests_total Total guardrail ingress requests received."
        )
        out.append("# TYPE guardrail_requests_total counter")
        out.append(f"guardrail_requests_total {req}")
        out.append(
            "# HELP guardrail_decisions_total Total guardrail ingress decisions made."
        )
        out.append("# TYPE guardrail_decisions_total counter")
        out.append(f"guardrail_decisions_total {dec}")
    except Exception:
        # Silently omit if legacy route not present in this build.
        pass
    return out


def _export_global_family_lines() -> List[str]:
    """
    Export global decision-family totals from telemetry.metrics.
    """
    lines: List[str] = []
    fam_totals = tmetrics.get_all_family_totals()
    if fam_totals:
        lines.append(
            "# HELP guardrail_decisions_family_total Decisions by family (global)."
        )
        lines.append("# TYPE guardrail_decisions_family_total counter")
        for fam, v in sorted(fam_totals.items()):
            lines.append(
                f'guardrail_decisions_family_total{{family="{fam}"}} {float(v)}'
            )
    return lines


def _export_rate_limited_lines() -> List[str]:
    """
    Export legacy rate-limited counter (separate from quotas).
    """
    v = tmetrics.get_rate_limited_total()
    lines = [
        "# HELP guardrail_rate_limited_total Requests rejected by legacy rate limiter.",
        "# TYPE guardrail_rate_limited_total counter",
        f"guardrail_rate_limited_total {float(v)}",
    ]
    return lines


@router.get("/metrics")
async def prometheus_metrics(_: Request) -> PlainTextResponse:
    """
    Prometheus exposition format:
      - Built-in registry metrics via prometheus_client.generate_latest
      - Custom text lines for global/tenant/bot family breakdowns
      - Optional legacy guardrail counters (if available)
    """
    # 1) prometheus_client registered metrics (e.g., quota rejects)
    chunks: List[str] = [generate_latest(REGISTRY).decode("utf-8")]

    # 2) Global family totals
    chunks.extend(_export_global_family_lines())

    # 3) Tenant/bot breakdown lines
    chunks.extend(tmetrics.export_family_breakdown_lines())

    # 4) Legacy guardrail counters (optional)
    chunks.extend(_safe_guardrail_legacy_totals())

    # 5) Legacy rate-limited counter
    chunks.extend(_export_rate_limited_lines())

    body = "\n".join(chunks)
    return PlainTextResponse(content=body, media_type=CONTENT_TYPE_LATEST)
