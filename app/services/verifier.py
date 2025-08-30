from __future__ import annotations

import hashlib
import os
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple


class Verdict(str, Enum):
    SAFE = "safe"
    UNSAFE = "unsafe"
    UNCLEAR = "unclear"


def content_fingerprint(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


# --- simple in-memory cache (can be replaced later) ---
_known_harmful: Dict[str, bool] = {}  # fp -> True


def mark_harmful(fp: str) -> None:
    _known_harmful[fp] = True


def is_known_harmful(fp: str) -> bool:
    return _known_harmful.get(fp, False)


# --- provider adapters (non-executing, classification-only) ---
ProviderFn = Callable[[str, Dict[str, Any]], Verdict]


def provider_gemini(text: str, meta: Dict[str, Any]) -> Verdict:
    hint = meta.get("hint") or ""
    if "force_unsafe" in hint:
        return Verdict.UNSAFE
    if "force_unclear" in hint:
        return Verdict.UNCLEAR
    return Verdict.SAFE


def provider_claude(text: str, meta: Dict[str, Any]) -> Verdict:
    hint = meta.get("hint") or ""
    if "force_unsafe" in hint:
        return Verdict.UNSAFE
    if "force_unclear" in hint:
        return Verdict.UNCLEAR
    return Verdict.SAFE


PROVIDERS: Dict[str, ProviderFn] = {
    "gemini": provider_gemini,
    "claude": provider_claude,
}


class Verifier:
    def __init__(self, providers_order: List[str]) -> None:
        self.providers_order = providers_order

    def assess_intent(
        self, text: str, meta: Optional[Dict[str, Any]] = None
    ) -> Tuple[Verdict, Optional[str]]:
        meta = meta or {}
        for name in self.providers_order:
            fn = PROVIDERS.get(name)
            if not fn:
                continue
            try:
                verdict = fn(text, meta)
                return verdict, name
            except Exception:
                continue
        return None, None  # type: ignore


def load_providers_order() -> List[str]:
    s = os.getenv("VERIFIER_PROVIDERS", "gemini,claude")
    return [p.strip() for p in s.split(",") if p.strip()]


def verifier_enabled() -> bool:
    return os.getenv("VERIFIER_ENABLED", "false").lower() == "true"
