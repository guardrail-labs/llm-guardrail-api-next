"""
UPIPE: Unified pipeline with lightweight detectors.
- Prompt injection phrases
- Secret-like patterns (OpenAI key, AWS AKIA, private keys)
- Long encoded blobs (base64/hex)

No external deps — stdlib only.
"""
import re
from dataclasses import dataclass
from typing import List


@dataclass
class Decision:
    rule_id: str
    rationale: str
    severity: str = "high"  # use "high" to trigger policy block
    category: str | None = None


_PI_PHRASES = [
    "ignore previous instructions",
    "disregard previous instructions",
    "reveal system prompt",
    "ignore all prior",
    "bypass",
    "developer mode",
    "override system",
]

# Obvious secret shapes (approximate)
_RE_OPENAI = re.compile(r"sk-[A-Za-z0-9]{20,}")
_RE_AWS_AKID = re.compile(r"AKIA[0-9A-Z]{16}")

_BASE64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_HEX_CHARS = set("0123456789abcdefABCDEF")


def _has_long_base64_blob(text: str, min_len: int = 200) -> bool:
    for token in text.split():
        if len(token) >= min_len and all(ch in _BASE64_CHARS for ch in token):
            return True
    # Also check a whitespace-stripped view
    compact = re.sub(r"\s+", "", text)
    return len(compact) >= min_len and all(ch in _BASE64_CHARS for ch in compact)


def _has_long_hex_blob(text: str, min_len: int = 200) -> bool:
    for token in text.split():
        if len(token) >= min_len and all(ch in _HEX_CHARS for ch in token):
            return True
    return False


def analyze(text: str) -> List[Decision]:
    decs: List[Decision] = []
    t = text.lower()

    # 1) Prompt-injection phrases
    for p in _PI_PHRASES:
        if p in t:
            decs.append(
                Decision(
                    rule_id="pi:prompt_injection",
                    category="prompt_injection",
                    rationale=f"Matched injection phrase: '{p}'",
                )
            )
            break

    # 2) Secrets
    has_private_key_header = "-----BEGIN " in text and " PRIVATE KEY-----" in text
    if _RE_OPENAI.search(text) or _RE_AWS_AKID.search(text) or has_private_key_header:
        decs.append(
            Decision(
                rule_id="secrets:api_key_like",
                category="secrets",
                rationale="Detected key-like pattern (OpenAI/AWS/private key header)",
            )
        )

    # 3) Encoded blobs
    if _has_long_base64_blob(text) or _has_long_hex_blob(text):
        decs.append(
            Decision(
                rule_id="payload:encoded_blob",
                category="payload",
                rationale="Detected long base64/hex blob",
            )
        )

    return decs
