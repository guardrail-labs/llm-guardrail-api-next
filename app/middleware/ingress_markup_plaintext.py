from __future__ import annotations

import json
from typing import Awaitable, Callable, List

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from app.observability.metrics import markup_ingress_report
from app.sanitizers.markup import looks_like_markup, strip_markup_to_text

_HDR_TENANT = "X-Guardrail-Tenant"
_HDR_BOT = "X-Guardrail-Bot"

# We do NOT mutate payloads. We expose derived plaintexts on request.state
# for downstream scanners/policies: request.state.guardrail_plaintexts: List[str]


def _collect_strings(obj) -> List[str]:
    out: List[str] = []
    if isinstance(obj, dict):
        for v in obj.values():
            out.extend(_collect_strings(v))
    elif isinstance(obj, list):
        for v in obj:
            out.extend(_collect_strings(v))
    elif isinstance(obj, str):
        out.append(obj)
    return out


class IngressMarkupPlaintextMiddleware(BaseHTTPMiddleware):
    """
    Detect HTML/SVG-ish markup in JSON string fields and extract plaintext.
    Does not modify the request body. Stores derived plaintext strings in:
      request.state.guardrail_plaintexts (list of str)
    Emits Prometheus counters for visibility.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable],
    ):
        tenant = request.headers.get(_HDR_TENANT, "")
        bot = request.headers.get(_HDR_BOT, "")

        ctype = request.headers.get("content-type", "").lower()
        raw = None
        plaintexts: List[str] = []
        changed_count = 0
        scripts_removed = 0
        styles_removed = 0
        foreign_removed = 0
        tags_removed = 0

        if "application/json" in ctype:
            raw = await request.body()
            if raw:
                try:
                    data = json.loads(raw)
                except Exception:
                    data = None
                if data is not None:
                    for s in _collect_strings(data):
                        if looks_like_markup(s):
                            txt, st = strip_markup_to_text(s)
                            if st.get("changed", 0):
                                changed_count += 1
                            scripts_removed += st.get("scripts_removed", 0)
                            styles_removed += st.get("styles_removed", 0)
                            foreign_removed += st.get("foreign_removed", 0)
                            tags_removed += st.get("tags_removed", 0)
                            if txt:
                                plaintexts.append(txt)

        # Attach derived plaintexts for downstream scanners (non-breaking)
        if plaintexts:
            request.state.guardrail_plaintexts = plaintexts

        # Re-inject body if consumed
        if raw is not None:

            async def receive() -> dict:
                return {"type": "http.request", "body": raw, "more_body": False}

            request = Request(request.scope, receive)

        # Metrics
        markup_ingress_report(
            tenant=tenant,
            bot=bot,
            fields_with_markup=changed_count,
            scripts_removed=scripts_removed,
            styles_removed=styles_removed,
            foreign_removed=foreign_removed,
            tags_removed=tags_removed,
        )

        return await call_next(request)
