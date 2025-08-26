"""Minimal Python client for the Guardrail API."""
from __future__ import annotations

from typing import Any, Dict, Optional

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
        self._client = httpx.Client(base_url=self.base_url, headers=headers, timeout=timeout)

    def guardrail(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"prompt": prompt}
        if context is not None:
            payload["context"] = context

        resp = self._client.post("/guardrail", json=payload)
        resp.raise_for_status()
        return resp.json()

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "GuardrailClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        self.close()
