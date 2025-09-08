from __future__ import annotations

from typing import Optional

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

    # Future: anthropic, vertex, etc.
    return None
