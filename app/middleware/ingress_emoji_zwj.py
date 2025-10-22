from __future__ import annotations

import json
from typing import Awaitable, Callable, List

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from app.observability.metrics import emoji_zwj_ingress_report
from app.sanitizers.unicode_emoji import analyze_emoji_sequences

_HDR_TENANT = "X-Guardrail-Tenant"
_HDR_BOT = "X-Guardrail-Bot"


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


class IngressEmojiZWJMiddleware(BaseHTTPMiddleware):
    """
    Surface hidden text carried by emoji ZWJ/TAG sequences.
    - Does not mutate payloads.
    - Appends any revealed ASCII from TAGs to request.state.guardrail_plaintexts.
    - Emits Prometheus counters.
    - Optionally marks request as sensitive when suspicious density is high.
    """

    # Sensitivity knobs (conservative defaults)
    sensitive_zwj_min = 4        # many joins in a single request
    sensitive_tag_chars_min = 6  # enough ASCII to matter

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable],
    ):
        tenant = request.headers.get(_HDR_TENANT, "")
        bot = request.headers.get(_HDR_BOT, "")

        ctype = request.headers.get("content-type", "").lower()
        raw = None

        total_fields = 0
        total_hidden_bytes = 0
        total_tag_seqs = 0
        total_zwj = 0
        total_controls = 0

        derived_texts: List[str] = []

        if "application/json" in ctype:
            raw = await request.body()
            if raw:
                try:
                    data = json.loads(raw)
                except Exception:
                    data = None
                if data is not None:
                    for s in _collect_strings(data):
                        total_fields += 1
                        revealed, st = analyze_emoji_sequences(s)
                        total_hidden_bytes += len(revealed.encode("utf-8")) if revealed else 0
                        total_tag_seqs += st.get("tag_seq", 0)
                        total_zwj += st.get("zwj", 0)
                        total_controls += st.get("controls_inside", 0)
                        if revealed:
                            # Expose for scanners/policies
                            derived_texts.append(f"[emoji-hidden] {revealed}")

        # Attach derived plaintexts (non-breaking)
        if derived_texts:
            existing = getattr(request.state, "guardrail_plaintexts", [])
            setattr(
                request.state,
                "guardrail_plaintexts",
                list(existing) + derived_texts, 
            )

        # Optionally mark sensitive to trigger timing normalization
        if total_tag_seqs > 0 and total_hidden_bytes >= self.sensitive_tag_chars_min:
            request.state.guardrail_sensitive = True
        elif total_zwj >= self.sensitive_zwj_min and total_controls > 0:
            request.state.guardrail_sensitive = True

        # Replay body if consumed
        if raw is not None:
            async def receive() -> dict:
                return {"type": "http.request", "body": raw, "more_body": False}
            request = Request(request.scope, receive)

        # Metrics
        emoji_zwj_ingress_report(
            tenant=tenant,
            bot=bot,
            fields=total_fields,
            tag_sequences=total_tag_seqs,
            zwj_count=total_zwj,
            controls=total_controls,
            hidden_bytes=total_hidden_bytes,
        )

        return await call_next(request)
