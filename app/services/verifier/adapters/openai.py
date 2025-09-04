from __future__ import annotations

import os
import time
from typing import Any, Dict

from app.services.verifier.interface import Verdict, VerifierAdapter

DEFAULT_MODEL = os.getenv("VERIFIER_OPENAI_MODEL", "gpt-4o-mini")
# label-only classification prompt
TIMEOUT_S = float(os.getenv("VERIFIER_TIMEOUT_S", "6.0"))
RETRIES = int(os.getenv("VERIFIER_RETRIES", "1"))


class OpenAIAdapter(VerifierAdapter):
    provider = "openai"

    def __init__(self, client=None):
        # client: injectable for tests (mock). Real impl would wrap openai SDK.
        self.client = client

    def classify(self, text: str, context: Dict[str, Any] | None = None) -> Verdict:
        # Timeout/retry skeleton (no external calls in unit tests)
        start = time.time()
        last_exc = None
        for _ in range(RETRIES + 1):
            try:
                # Pseudo-call; replace with real SDK usage. Tests will mock return.
                if self.client is None:
                    # Offline default: be conservative -> "unclear"
                    return Verdict(
                        label="unclear",
                        confidence=0.51,
                        provider=self.provider,
                        meta={"offline": True},
                    )
                resp = self.client.classify(text=text, model=DEFAULT_MODEL, context=context or {})
                label = resp["label"]
                conf = float(resp.get("confidence", 0.5))
                return Verdict(
                    label=label,
                    confidence=conf,
                    provider=self.provider,
                    meta={"model": DEFAULT_MODEL},
                )
            except Exception as e:  # noqa: BLE001
                last_exc = e
                if time.time() - start > TIMEOUT_S:
                    break
        # On failure: fail-safe to unclear
        return Verdict(
            label="unclear",
            confidence=0.5,
            provider=self.provider,
            meta={"error": str(last_exc) if last_exc else "timeout"},
        )
