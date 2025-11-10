from __future__ import annotations

from typing import Optional

from app.settings import ANTHROPIC_API_KEY, VERIFIER_ANTHROPIC_MODEL

from .base import Provider
from .local_rules import LocalRulesProvider


def build_provider(name: str) -> Optional[Provider]:
    """
    Factory for provider instances by canonical name.
    Unknown/unsupported names return None (skipped by Verifier).
    """
    key = (name or "").strip().lower()
    if key in ("local", "local_rules"):
        return LocalRulesProvider()

    if key in ("openai", "gpt"):
        try:
            from .openai_adapter import OpenAIProvider  # lazy import

            return OpenAIProvider()
        except Exception:
            return None

    if key in ("anthropic", "claude"):
        try:
            from .anthropic_adapter import AnthropicProvider

            return AnthropicProvider(ANTHROPIC_API_KEY, VERIFIER_ANTHROPIC_MODEL)
        except Exception:
            return None
    return None
