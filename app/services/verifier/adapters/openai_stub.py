from __future__ import annotations

from typing import Any, Mapping

from .base import Verdict, VerifierAdapter


class OpenAIStubAdapter(VerifierAdapter):
    def assess(self, payload: Mapping[str, Any]) -> Verdict:
        # Placeholder: real implementation will call OpenAI moderation/reasoner.
        return "unclear"
