# app/middleware/egress_output_inspect.py
from __future__ import annotations

from typing import Awaitable, Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.observability.metrics import egress_output_report
from app.sanitizers.unicode_sanitizer import sanitize_text
from app.sanitizers.unicode_emoji import analyze_emoji_sequences
from app.sanitizers.markup import looks_like_markup, strip_markup_to_text


class EgressOutputInspectMiddleware(BaseHTTPMiddleware):
    """
    Inspect small JSON/text responses for:
      - zero-width/Bidi/confusable indicators (via sanitize_text stats)
      - emoji TAG/ZWJ hidden ASCII (no mutation)
      - HTML/SVG markup presence
    Does NOT change the body. Adds a diagnostic header:
      X-Guardrail-Egress-Flags: emoji,zwc,markup
    Emits Prometheus counters via egress_output_report().
    """

    # Only inspect bodies up to this size (bytes)
    max_bytes = 128 * 1024

    def _is_texty(self, content_type: str) -> bool:
        ct = (content_type or "").lower()
        return (
            "application/json" in ct
            or "text/plain" in ct
            or ct.startswith("text/")
        )

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        resp = await call_next(request)

        # Only inspect if we can access a concrete body without streaming.
        # Avoid touching internals like `body_iterator` to stay mypy-safe.
        body: bytes | None = getattr(resp, "body", None)
        ctype = resp.headers.get("content-type", "")

        if not body or not self._is_texty(ctype) or len(body) > self.max_bytes:
            return resp

        try:
            text = body.decode("utf-8", errors="replace")
        except Exception:
            return resp

        # 1) Unicode controls / bidi / zero-width (stats only)
        _, ustats = sanitize_text(text)
        zero_width = int(ustats.get("zero_width_removed", 0) > 0)
        bidi = int(ustats.get("bidi_controls_removed", 0) > 0)
        conf = int(ustats.get("confusables_mapped", 0) > 0)

        # 2) Emoji TAG/ZWJ derived ASCII (do not inject)
        revealed, estats = analyze_emoji_sequences(text)
        emoji_hidden_bytes = len(revealed.encode("utf-8")) if revealed else 0
        emoji_hit = int(emoji_hidden_bytes > 0 or estats.get("zwj", 0) > 0)

        # 3) Markup presence
        markup_hit = 0
        if looks_like_markup(text):
            _, mstats = strip_markup_to_text(text)
            if any(
                mstats.get(k, 0) > 0
                for k in (
                    "scripts_removed",
                    "styles_removed",
                    "foreign_removed",
                    "tags_removed",
                )
            ):
                markup_hit = 1

        # Emit metrics
        egress_output_report(
            zero_width=zero_width,
            bidi=bidi,
            confusable=conf,
            emoji_hidden_bytes=emoji_hidden_bytes,
            emoji_zwj=estats.get("zwj", 0),
            markup=markup_hit,
        )

        # Add compact diagnostic header (non-breaking)
        flags: list[str] = []
        if emoji_hit:
            flags.append("emoji")
        if zero_width or bidi or conf:
            flags.append("zwc")
        if markup_hit:
            flags.append("markup")
        if flags:
            prev = resp.headers.get("x-guardrail-egress-flags")
            joined = ",".join(flags) if not prev else f"{prev},{','.join(flags)}"
            resp.headers["X-Guardrail-Egress-Flags"] = joined

        return resp
