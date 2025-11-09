from __future__ import annotations

import json
import time
from typing import Awaitable, Callable, Dict, List, Tuple

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.observability.metrics import probing_ingress_report
from app.risk.probing import (
    collect_strings,
    count_leakage_hints,
    jaccard_similarity,
    rate_store,
)
from app.risk.session_risk import session_risk_store

_HDR_TENANT = "X-Guardrail-Tenant"
_HDR_BOT = "X-Guardrail-Bot"
_HDR_SESSION = "X-Guardrail-Session"

# --- TTL cache for last_text (per tenant/bot/session) -----------------------
_LAST_TEXT_TTL = 15 * 60  # seconds
_LAST_TEXT_MAX = 50_000
# key -> (ts, text)
_LAST_TEXT: Dict[str, Tuple[float, str]] = {}


def _lt_key(tenant: str, bot: str, sess: str) -> str:
    return f"{tenant}|{bot}|{sess}"


def _lt_set(tenant: str, bot: str, sess: str, text: str) -> None:
    now = time.time()
    _LAST_TEXT[_lt_key(tenant, bot, sess)] = (now, text)
    # light GC
    if len(_LAST_TEXT) > _LAST_TEXT_MAX:
        cutoff = now - _LAST_TEXT_TTL
        to_del = [k for k, (ts, _) in _LAST_TEXT.items() if ts < cutoff]
        for k in to_del:
            _LAST_TEXT.pop(k, None)
        if len(_LAST_TEXT) > _LAST_TEXT_MAX:
            # drop oldest ~5%
            items = sorted(_LAST_TEXT.items(), key=lambda kv: kv[1][0])
            cut = max(1, len(items) // 20)
            for k, _ in items[:cut]:
                _LAST_TEXT.pop(k, None)


def _lt_get(tenant: str, bot: str, sess: str) -> str:
    now = time.time()
    ts_text = _LAST_TEXT.get(_lt_key(tenant, bot, sess))
    if not ts_text:
        return ""
    ts, text = ts_text
    if now - ts > _LAST_TEXT_TTL:
        _LAST_TEXT.pop(_lt_key(tenant, bot, sess), None)
        return ""
    return text


# ---------------------------------------------------------------------------


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
    """
    Detect probing via:
      - Rolling rate per session (hits within short window).
      - Leakage hint phrases.
      - High similarity to prior text (near-duplicate probing).
    Emits Prometheus metrics and bumps session risk; does not mutate payloads.
    """

    # Defaults; can be overridden by config in a later PR
    rate_window_secs = 30.0
    max_reqs_per_window = 20
    sim_threshold = 0.8  # Jaccard on char 3-grams
    min_text_len_for_sim = 24

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
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

        last_text = _lt_get(tenant, bot, sess)
        if texts and last_text:
            for text in texts:
                if (
                    len(text) >= self.min_text_len_for_sim
                    and len(last_text) >= self.min_text_len_for_sim
                ):
                    if jaccard_similarity(text, last_text) >= self.sim_threshold:
                        similarity_hits += 1
                        break

        if texts:
            for text in texts:
                if len(text) >= self.min_text_len_for_sim:
                    _lt_set(tenant, bot, sess, text)
                    break

        delta = 0.0
        if rate_exceeded:
            delta += 1.0
        if leakage_hits:
            delta += min(1.0, 0.25 * float(leakage_hits))
        if similarity_hits:
            delta += 0.5
        if delta:
            store = session_risk_store()
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
