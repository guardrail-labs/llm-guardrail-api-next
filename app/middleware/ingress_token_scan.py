from __future__ import annotations

import json
from typing import Awaitable, Callable, List

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from app.scanners.token_sequence_detector import find_terms_tokenized
from app.observability.metrics import token_scan_report
from app.services.config_store import get_config


_HDR_TENANT = "X-Guardrail-Tenant"
_HDR_BOT = "X-Guardrail-Bot"


def _iter_strings(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _iter_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _iter_strings(v)
    elif isinstance(obj, str):
        yield obj


class IngressTokenScanMiddleware(BaseHTTPMiddleware):
    """
    Scans inbound JSON string fields using tokenizer-aware windows to
    detect sensitive terms split across tokens. Does not mutate payloads.
    Emits Prometheus counters per term.
    """

    def _terms(self) -> List[str]:
        cfg = dict(get_config())
        terms = cfg.get("token_scan_terms") or []
        if not isinstance(terms, list):
            return []
        out: List[str] = []
        for t in terms:
            if isinstance(t, str) and t.strip():
                out.append(t.strip())
        return out

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable],
    ):
        tenant = request.headers.get(_HDR_TENANT, "")
        bot = request.headers.get(_HDR_BOT, "")

        ctype = request.headers.get("content-type", "").lower()
        if "application/json" not in ctype:
            return await call_next(request)

        raw = await request.body()
        if not raw:
            return await call_next(request)

        try:
            data = json.loads(raw)
        except Exception:
            return await call_next(request)

        terms = self._terms()
        if not terms:
            # No configured terms → nothing to do
            return await call_next(request)

        # Aggregate hits across all string fields
        agg: dict[str, int] = {}
        for s in _iter_strings(data):
            hits = find_terms_tokenized(s, terms)
            for term, cnt in hits.items():
                agg[term] = agg.get(term, 0) + cnt

        if agg:
            token_scan_report(tenant=tenant, bot=bot, hits=agg)

        return await call_next(request)
