from __future__ import annotations

import json
import time
from typing import Awaitable, Callable, List

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from app.observability.metrics import probing_ingress_report
from app.risk.probing import (
    DEFAULT_MAX_REQS_PER_WINDOW,
    DEFAULT_RATE_WINDOW_SECS,
    MIN_TEXT_LEN_FOR_SIM,
    collect_strings,
    count_leakage_hints,
    jaccard_similarity,
    rate_store,
)
from app.risk.session_risk import session_risk_store

_HDR_TENANT = "X-Guardrail-Tenant"
_HDR_BOT = "X-Guardrail-Bot"
_HDR_SESSION = "X-Guardrail-Session"


def _labels(request: Request) -> tuple[str, str, str]:
    headers = request.headers
    tenant = headers.get(_HDR_TENANT, "")
    bot = headers.get(_HDR_BOT, "")
    sess = headers.get(_HDR_SESSION, "")
    if not sess:
        ip = request.client.host if request.client else ""
        ua = headers.get("user-agent", "")
        sess = f"{ip}:{ua[:64]}"
    return tenant, bot, sess


class IngressProbingMiddleware(BaseHTTPMiddleware):
    rate_window_secs = DEFAULT_RATE_WINDOW_SECS
    max_reqs_per_window = DEFAULT_MAX_REQS_PER_WINDOW
    sim_threshold = 0.8

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable],
    ):
        tenant, bot, sess = _labels(request)
        now = time.time()

        rate_store_instance = rate_store()
        hits_in_window = rate_store_instance.hit(
            f"{tenant}|{bot}|{sess}", now, self.rate_window_secs
        )
        rate_exceeded = 1 if hits_in_window > self.max_reqs_per_window else 0

        raw_body = None
        texts: List[str] = []
        leakage_hits = 0
        similarity_hits = 0

        content_type = request.headers.get("content-type", "").lower()
        if "application/json" in content_type:
            raw_body = await request.body()
            if raw_body:
                try:
                    data = json.loads(raw_body)
                except Exception:
                    data = None
                if data is not None:
                    texts = collect_strings(data)
                    leakage_hits = count_leakage_hints(texts)

        store = session_risk_store()
        last_key = f"__last_text__:{tenant}:{bot}:{sess}"
        last_text = getattr(store, last_key, "")  
        if texts and last_text:
            for text in texts:
                if (
                    len(text) >= MIN_TEXT_LEN_FOR_SIM
                    and len(last_text) >= MIN_TEXT_LEN_FOR_SIM
                ):
                    if jaccard_similarity(text, last_text) >= self.sim_threshold:
                        similarity_hits += 1
                        break
        if texts:
            for text in texts:
                if len(text) >= MIN_TEXT_LEN_FOR_SIM:
                    setattr(store, last_key, text)  
                    break

        delta = 0.0
        if rate_exceeded:
            delta += 1.0
        if leakage_hits:
            delta += min(1.0, 0.25 * float(leakage_hits))
        if similarity_hits:
            delta += 0.5
        if delta:
            store.bump(tenant, bot, sess, delta, ttl_seconds=900.0)

        probing_ingress_report(
            tenant=tenant,
            bot=bot,
            rate_exceeded=rate_exceeded,
            rate_hits=hits_in_window,
            leakage_hits=leakage_hits,
            similarity_hits=similarity_hits,
        )

        if raw_body is not None:
            async def receive() -> dict:
                return {"type": "http.request", "body": raw_body, "more_body": False}

            request = Request(request.scope, receive)

        return await call_next(request)
