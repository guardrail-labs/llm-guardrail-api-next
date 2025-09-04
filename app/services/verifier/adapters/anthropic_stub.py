from __future__ import annotations

from typing import Any, Mapping

from .base import Verdict, VerifierAdapter


class AnthropicStubAdapter(VerifierAdapter):
    def assess(self, payload: Mapping[str, Any]) -> Verdict:
        # Placeholder: real implementation will call Anthropic safety endpoint.
        return "unclear"
