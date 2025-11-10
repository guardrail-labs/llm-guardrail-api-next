from __future__ import annotations

import os
from typing import Any, Dict, Optional

from app.services.verifier.providers.base import ProviderRateLimited


class OpenAIProvider:
    """
    Optional provider that calls OpenAI. No hard dependency:
    - If SDK/env missing -> raises at construct-time and will be skipped by
      the factory.
    - If runtime error -> Verifier will catch and fail over.
    """

    name = "openai"

    def __init__(self) -> None:
        api_key = os.getenv("OPENAI_API_KEY", "").strip()
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY missing")
        # Lazy import; do not pin types
        import openai  # mypy treats this as Any (no stubs required)

        self._openai = openai
        self._openai.api_key = api_key

    async def assess(self, text: str, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        # Minimal mapping; replace with real SDK call as needed.
        prompt = f"Classify the user intent as safe/unsafe/ambiguous:\n\n{text}"
        try:
            resp = await _call_openai_chat(self._openai, prompt)
            label = str(resp.get("label", "ambiguous")).lower()
            reason = str(resp.get("reason") or "")
            if label not in ("safe", "unsafe", "ambiguous"):
                label = "ambiguous"
            return {
                "status": label,
                "reason": reason,
                "tokens_used": int(resp.get("tokens_used") or max(1, len(text) // 4)),
            }
        except self._openai.RateLimitError as e:
            retry_after = None
            try:
                hdrs = getattr(e, "response", None)
                if hdrs and getattr(hdrs, "headers", None):
                    ra = hdrs.headers.get("retry-after") or hdrs.headers.get("Retry-After")
                    if ra is not None:
                        retry_after = float(ra)
            except Exception:  # pragma: no cover
                retry_after = None
            raise ProviderRateLimited("rate_limited", retry_after_s=retry_after)
        except self._openai.APIError as e:
            if getattr(e, "status_code", None) == 429:
                raise ProviderRateLimited("rate_limited", retry_after_s=None)
            raise
        except Exception:
            # Let the Verifier decide to fail over
            raise


async def _call_openai_chat(openai_mod: Any, prompt: str) -> Dict[str, Any]:
    """
    Tiny indirection to allow easy monkeypatching in tests.
    Replace with actual SDK logic (chat.completions.create, etc.).
    """
    # Pseudo response so the adapter is structurally testable without real calls.
    return {"label": "ambiguous", "reason": "", "tokens_used": max(1, len(prompt) // 4)}
