# app/middleware/ingress_risk.py
from __future__ import annotations

import json
from typing import Awaitable, Callable, Dict

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from app.observability.metrics import session_risk_report
from app.risk.session_risk import session_risk_store

# Safe config import wrapper; avoids mypy attr-defined error if get_config is absent.
try:
    # mypy: the symbol may be injected at runtime in this project
    from app.settings import get_config as _get_config  # type: ignore[attr-defined]

    def _read_cfg() -> Dict[str, object]:
        try:
            cfg = _get_config()  
            return dict(cfg) if isinstance(cfg, dict) else {}
        except Exception:
            return {}

except Exception:
    def _read_cfg() -> Dict[str, object]:
        return {}

_HDR_TENANT = "X-Guardrail-Tenant"
_HDR_BOT = "X-Guardrail-Bot"
_HDR_SESSION = "X-Guardrail-Session"


def _labels(req: Request) -> tuple[str, str, str]:
    h = req.headers
    tenant = h.get(_HDR_TENANT, "")
    bot = h.get(_HDR_BOT, "")
    sess = h.get(_HDR_SESSION, "")
    # Best-effort session fallback: IP + UA prefix (coarse)
    if not sess:
        ip = req.client.host if req.client else ""
        ua = h.get("user-agent", "")
        sess = f"{ip}:{ua[:64]}"
    return tenant, bot, sess


def _suspicion_score_from_json(data: object) -> float:
    # Very light heuristic to nudge risk; scanners already handle details.
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
    Short-lived session risk score per requester that decays over time.
    Emits Prometheus metrics; does not mutate payloads.
    """

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable],
    ):
        tenant, bot, sess = _labels(request)

        cfg = _read_cfg()
        half_life = float(cfg.get("risk_half_life_seconds", 180.0))  # type: ignore[arg-type]
        ttl = float(cfg.get("risk_ttl_seconds", 900.0))  # type: ignore[arg-type]

        store = session_risk_store()
        base = store.decay_and_get(tenant, bot, sess, half_life)

        # Peek JSON once (replay body afterward)
        delta = 0.0
        raw = None
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
        session_risk_report(
            tenant=tenant,
            bot=bot,
            session=sess,
            base=base,
            delta=delta,
            score=score,
        )

        # Re-inject original body if consumed
        async def receive() -> dict:
            body = raw if raw is not None else b""
            return {
                "type": "http.request",
                "body": body,
                "more_body": False,
            }

        if raw is not None:
            request = Request(request.scope, receive)

        return await call_next(request)
