# file: app/services/llm_client.py
from __future__ import annotations

import json
import os
from typing import Any, Dict, Iterable, List, Tuple

try:
    import httpx
except Exception:  # pragma: no cover - httpx is optional for local-echo
    httpx = None  # type: ignore[assignment]


class BaseLLMClient:
    def chat(
        self, messages: List[Dict[str, str]], model: str
    ) -> Tuple[str, Dict[str, Any]]:
        raise NotImplementedError

    def chat_stream(
        self, messages: List[Dict[str, str]], model: str
    ) -> Tuple[Iterable[str], Dict[str, Any]]:
        """
        Stream assistant text pieces for SSE. Implemented by providers.
        """
        raise NotImplementedError


class LocalEchoClient(BaseLLMClient):
    """
    Safe default: never leaves the box. Used by CI/tests.
    """

    def _last_user(self, messages: List[Dict[str, str]]) -> str:
        last = ""
        for m in reversed(messages or []):
            if m.get("role") == "user":
                last = str(m.get("content") or "")
                break
        return last

    def chat(
        self, messages: List[Dict[str, str]], model: str
    ) -> Tuple[str, Dict[str, Any]]:
        text = f"Echo: {self._last_user(messages)}".strip()
        meta = {"provider": "local-echo", "model": model or "demo"}
        return text, meta

    def chat_stream(
        self, messages: List[Dict[str, str]], model: str
    ) -> Tuple[Iterable[str], Dict[str, Any]]:
        text = f"Echo: {self._last_user(messages)}".strip()

        def gen() -> Iterable[str]:
            # One-shot piece is fine for tests; caller supports any granularity.
            if text:
                yield text

        meta = {"provider": "local-echo", "model": model or "demo"}
        return gen(), meta


class OpenAIClient(BaseLLMClient):
    """
    Minimal OpenAI Chat Completions client (non-stream + stream).
    - Honors a conservative timeout (OPENAI_HTTP_TIMEOUT, default 15s).
    - Never logs request bodies or API keys.
    - Returns (text, meta) / (iter(text_parts), meta).
    """

    def __init__(self, api_key: str, base_url: str | None = None) -> None:
        if httpx is None:
            raise RuntimeError("httpx is required for OpenAI provider")
        self.api_key = api_key
        self.base_url = (base_url or "https://api.openai.com").rstrip("/")
        self.timeout = float(os.environ.get("OPENAI_HTTP_TIMEOUT", "15.0"))

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def chat(
        self, messages: List[Dict[str, str]], model: str
    ) -> Tuple[str, Dict[str, Any]]:
        url = f"{self.base_url}/v1/chat/completions"
        payload: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": False,
            "temperature": 0.2,
        }
        with httpx.Client(timeout=self.timeout) as client:
            r = client.post(url, headers=self._headers(), json=payload)
            r.raise_for_status()
            data = r.json()
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

    def chat_stream(
        self, messages: List[Dict[str, str]], model: str
    ) -> Tuple[Iterable[str], Dict[str, Any]]:
        """
        Stream using OpenAI SSE.
        Yields only delta.content pieces; role/tool events are ignored.
        """
        url = f"{self.base_url}/v1/chat/completions"
        payload: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": True,
            "temperature": 0.2,
        }

        def gen() -> Iterable[str]:
            with httpx.Client(timeout=self.timeout) as client:
                with client.stream(
                    "POST", url, headers=self._headers(), json=payload
                ) as resp:
                    resp.raise_for_status()
                    for line in resp.iter_lines():
                        if not line:
                            continue
                        if isinstance(line, bytes):
                            try:
                                line = line.decode("utf-8", "ignore")
                            except Exception:
                                continue
                        line = line.strip()
                        if not line.startswith("data:"):
                            continue
                        data_str = line[5:].strip()
                        if data_str == "[DONE]":
                            break
                        try:
                            obj = json.loads(data_str)
                        except Exception:
                            continue
                        for ch in obj.get("choices") or []:
                            delta = ch.get("delta") or {}
                            piece = delta.get("content")
                            if piece:
                                yield str(piece)

        meta = {"provider": "openai", "model": model}
        return gen(), meta


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
            return LocalEchoClient()
        base_url = os.environ.get("OPENAI_BASE_URL") or None
        try:
            return OpenAIClient(api_key=api_key, base_url=base_url)
        except Exception:
            return LocalEchoClient()
    return LocalEchoClient()
