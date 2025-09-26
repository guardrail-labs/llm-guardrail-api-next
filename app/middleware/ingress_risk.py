from __future__ import annotations

import json
from typing import Awaitable, Callable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from app.observability.metrics import session_risk_report
from app.risk.session_risk import session_risk_store
from app.services.config_store import get_config

_HDR_TENANT = "X-Guardrail-Tenant"
_HDR_BOT = "X-Guardrail-Bot"
_HDR_SESSION = "X-Guardrail-Session"

def _labels(req: Request) -> tuple[str, str, str]:
    h = req.headers
    tenant = h.get(_HDR_TENANT, "")
    bot = h.get(_HDR_BOT, "")
    sess = h.get(_HDR_SESSION, "")
    # Best-effort session fallback: IP + UA hash (coarse)
    if not sess:
        ip = req.client.host if req.client else ""
        ua = h.get("user-agent", "")
        sess = f"{ip}:{ua[:64]}"
    return tenant, bot, sess

def _suspicion_score_from_json(data: object) -> float:
    # Very light heuristic: add tiny increments for “hot” indicators.
    # Token scan metrics and other middlewares already capture detail.
    if not isinstance(data, (dict, list, str)):
        return 0.0
    s = 0.0
    if isinstance(data, str):
        txt = data.casefold()
        if "ignore previous" in txt or "follow these hidden" in txt:
            s += 1.0
        if "password" in txt or "api_key" in txt:
            s += 0.5
        return s
    if isinstance(data, list):
        return sum(_suspicion_score_from_json(v) for v in data)
    # dict
    for k, v in data.items():
        if isinstance(k, str):
            kk = k.casefold()
            if kk in {"prompt", "system", "hidden", "jailbreak"}:
                s += 0.5
        s += _suspicion_score_from_json(v)
    return s

class IngressRiskMiddleware(BaseHTTPMiddleware):
    """
    Compute and update a short-lived session risk score per request,
    based on light heuristics and previously accumulated risk.
    Emits Prometheus metrics. Does not mutate payloads.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable],
    ):
        tenant, bot, sess = _labels(request)
        cfg = dict(get_config())
        half_life = float(cfg.get("risk_half_life_seconds", 180.0))
        ttl = float(cfg.get("risk_ttl_seconds", 900.0))

        # Start from decayed score
        store = session_risk_store()
        base = store.decay_and_get(tenant, bot, sess, half_life)

        # Peek JSON once (other middlewares may also read body)
        delta = 0.0
        ctype = request.headers.get("content-type", "").lower()
        if "application/json" in ctype:
            raw = await request.body()
            if raw:
                try:
                    data = json.loads(raw)
                except Exception:
                    data = None
                if data is not None:
                    delta += _suspicion_score_from_json(data)

        # Bump score and emit metric
        score = store.bump(tenant, bot, sess, delta, ttl_seconds=ttl)
        session_risk_report(tenant=tenant, bot=bot, session=sess, base=base, delta=delta, score=score)

        # Re-inject original body if we consumed it
        async def receive() -> dict:
            return {"type": "http.request", "body": raw if "raw" in locals() else b"", "more_body": False}
        if "raw" in locals():
            request = Request(request.scope, receive)

        return await call_next(request)
