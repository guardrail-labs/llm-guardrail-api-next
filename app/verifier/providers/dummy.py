from __future__ import annotations

import time

from app.verifier.base import VerifierTimeout, VerifyInput, VerifyResult


class DummyVerifier:
    """
    Minimal provider used in tests and as a template.
    Behaviors can be toggled via constructor flags.
    """

    def __init__(
        self,
        name: str = "dummy",
        healthy: bool = True,
        fail: bool = False,
        sleep_s: float = 0.0,
    ) -> None:
        self.name = name
        self._healthy = healthy
        self._fail = fail
        self._sleep_s = sleep_s

    def health(self) -> bool:
        return self._healthy

    def verify(self, req: VerifyInput, timeout_s: float = 5.0) -> VerifyResult:
        if self._sleep_s > 0:
            time.sleep(min(self._sleep_s, timeout_s))
        if self._sleep_s > timeout_s:
            raise VerifierTimeout(f"timeout after {timeout_s}s")
        if self._fail:
            raise RuntimeError("provider error")
        # Allow trivial requests; block if the word "blockme" is present.
        txt = (req.text or "").lower()
        if "blockme" in txt:
            return VerifyResult(allowed=False, reason="policy_violation", confidence=0.9)
        return VerifyResult(allowed=True, reason="ok", confidence=0.99)
