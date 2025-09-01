from __future__ import annotations

import os
from typing import Any, Dict, List, Tuple

try:
    import httpx
except Exception:  # pragma: no cover - httpx is optional for local-echo
    httpx = None  # type: ignore[assignment]


class BaseLLMClient:
    def chat(self, messages: List[Dict[str, str]], model: str) -> Tuple[str, Dict[str, Any]]:
        raise NotImplementedError


class LocalEchoClient(BaseLLMClient):
    """
    Safe default: never leaves the box. Used by CI/tests.
    """
    def chat(self, messages: List[Dict[str, str]], model: str) -> Tuple[str, Dict[str, Any]]:
        last = ""
        for m in reversed(messages or []):
            if m.get("role") == "user":
                last = str(m.get("content") or "")
                break
        text = f"Echo: {last}".strip()
        meta = {"provider": "local-echo", "model": model or "demo"}
        return text, meta


class OpenAIClient(BaseLLMClient):
    """
    Minimal non-streaming OpenAI Chat Completions call.
    - Honors a conservative 15s timeout.
    - Never logs request bodies or API keys.
    - Returns (text, meta) where meta includes provider/model.
    """
    def __init__(self, api_key: str, base_url: str | None = None) -> None:
        if httpx is None:
            raise RuntimeError("httpx is required for OpenAI provider")
        self.api_key = api_key
        # Allow alternate base URL (Azure/OpenAI-compatible proxies)
        self.base_url = (base_url or "https://api.openai.com").rstrip("/")
        self.timeout = float(os.environ.get("OPENAI_HTTP_TIMEOUT", "15.0"))

    def chat(self, messages: List[Dict[str, str]], model: str) -> Tuple[str, Dict[str, Any]]:
        url = f"{self.base_url}/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        # Keep payload minimal & safe; no function/tool calls here yet.
        payload: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": False,
            "temperature": 0.2,
        }
        # Network call
        with httpx.Client(timeout=self.timeout) as client:
            r = client.post(url, headers=headers, json=payload)
            r.raise_for_status()
            data = r.json()
        # Extract first text
        text = ""
        try:
            choices = data.get("choices") or []
            if choices:
                text = (choices[0].get("message") or {}).get("content") or ""
        except Exception:
            text = ""
        meta = {
            "provider": "openai",
            "model": model,
            "usage": data.get("usage") or None,
            "id": data.get("id") or "",
        }
        return text, meta


def _bool_env(name: str, default: bool = False) -> bool:
    v = (os.environ.get(name) or "").strip().lower()
    if v in ("1", "true", "yes", "y", "on"):
        return True
    if v in ("0", "false", "no", "n", "off"):
        return False
    return default


def get_client() -> BaseLLMClient:
    """
    Select a provider by environment:
      - LLM_PROVIDER=openai + OPENAI_API_KEY => OpenAIClient
      - else => LocalEchoClient
    Optional:
      - OPENAI_BASE_URL to point at Azure/proxy compat endpoints.
    """
    provider = (os.environ.get("LLM_PROVIDER") or "").strip().lower()
    if provider == "openai":
        api_key = os.environ.get("OPENAI_API_KEY") or ""
        if not api_key:
            # Fail closed to local echo rather than raising in production boot
            return LocalEchoClient()
        base_url = os.environ.get("OPENAI_BASE_URL") or None
        try:
            return OpenAIClient(api_key=api_key, base_url=base_url)
        except Exception:
            # If httpx is missing or init fails, fall back safely.
            return LocalEchoClient()
    return LocalEchoClient()
