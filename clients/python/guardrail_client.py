"""Minimal typed Python client for the Guardrail API."""
from __future__ import annotations

from types import TracebackType
from typing import Any, Dict, Optional, cast

import httpx


class GuardrailClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        use_bearer: bool = False,
        timeout: float = 10.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.use_bearer = use_bearer
        self.timeout = timeout

        headers = (
            {"Authorization": f"Bearer {api_key}"}
            if use_bearer
            else {"X-API-Key": api_key}
        )
        self._client = httpx.Client(
            base_url=self.base_url, headers=headers, timeout=timeout
        )

    # Backwards-compat wrapper for older usage (maps to /guardrail/evaluate)
    def guardrail(self, prompt: str) -> Dict[str, Any]:
        return self.evaluate(text=prompt)

    def evaluate(self, text: str, request_id: Optional[str] = None) -> Dict[str, Any]:
        """
        POST /guardrail/evaluate

        Payload:
            {"text": str, "request_id": Optional[str]}

        Returns (per API contract):
            {
              "request_id": str,
              "action": str,
              "transformed_text": str,
              "decisions": list[dict]
            }
        """
        payload: Dict[str, Any] = {"text": text}
        if request_id is not None:
            payload["request_id"] = request_id

        resp = self._client.post("/guardrail/evaluate", json=payload)
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict):
            raise TypeError("Expected dict response from /guardrail/evaluate")
        return cast(Dict[str, Any], data)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "GuardrailClient":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()
