from __future__ import annotations

from typing import Any, Dict, List, Tuple


class LLMClient:
    """
    Minimal pluggable client. Default is a safe local echo that never leaves the box.
    Swap this out later for a real provider (OpenAI, Azure, etc.).
    """

    def chat(self, messages: List[Dict[str, str]], model: str) -> Tuple[str, Dict[str, Any]]:
        """
        Return (text, meta). Default: echo the last user message with a friendly prefix.
        """
        last = ""
        for m in reversed(messages or []):
            if m.get("role") == "user":
                last = str(m.get("content") or "")
                break
        text = f"Echo: {last}".strip()
        meta = {"provider": "local-echo", "model": model or "demo"}
        return text, meta


def get_client() -> LLMClient:
    # Later: env-driven dynamic loading; for now, safe default client.
    return LLMClient()
