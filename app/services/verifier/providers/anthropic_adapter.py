from __future__ import annotations

from typing import Any, Dict, Optional

from app.services.verifier.providers.base import ProviderRateLimited


class AnthropicProvider:
    """
    Optional Anthropic adapter.
    - Construct-time requires ANTHROPIC_API_KEY, else raise -> factory skips.
    - Runtime errors bubble to Verifier (which fails over).
    """

    name = "anthropic"

    def __init__(self, api_key: str, model: str) -> None:
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY missing")
        self._api_key = api_key
        self._model = model
        # Lazy import; no typing dependency
        import anthropic

        self._anthropic = anthropic.Anthropic(api_key=api_key)
        self._anthropic_mod = anthropic

    async def assess(self, text: str, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Map Anthropic response into our schema:
          {"status": "...", "reason": "...", "tokens_used": int}
        """
        prompt = _build_prompt(text, meta or {})
        try:
            resp = await _call_anthropic_chat(self._anthropic, self._model, prompt)
            label = str(resp.get("label", "ambiguous")).lower()
            reason = str(resp.get("reason") or "")
            if label not in ("safe", "unsafe", "ambiguous"):
                label = "ambiguous"
            tokens = int(resp.get("tokens_used") or max(1, len(text) // 4))
            return {"status": label, "reason": reason, "tokens_used": tokens}
        except self._anthropic_mod.RateLimitError as e:
            retry_after = getattr(e, "retry_after", None)
            raise ProviderRateLimited("rate_limited", retry_after_s=retry_after)
        except self._anthropic_mod.APIStatusError as e:
            if getattr(e, "status_code", None) == 429:
                raise ProviderRateLimited("rate_limited", retry_after_s=None)
            raise
        except Exception:
            # Let the Verifier pipeline decide to fail over
            raise


def _build_prompt(text: str, meta: Dict[str, Any]) -> str:
    # Keep simple/deterministic; you can evolve prompt later.
    return f"Classify as safe/unsafe/ambiguous:\n\n{text}"


async def _call_anthropic_chat(client: Any, model: str, prompt: str) -> Dict[str, Any]:
    """
    Indirection for testing. Replace with real SDK call if desired.
    For example (sync style):
        client.messages.create(model=model, max_tokens=64,
                               messages=[{'role':'user','content':prompt}])
    """
    # Return an "ambiguous" pseudo-response for structural tests.
    return {"label": "ambiguous", "reason": "", "tokens_used": max(1, len(prompt) // 4)}
