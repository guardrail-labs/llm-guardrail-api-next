# app/sanitizers/unicode_sanitizer.py
from __future__ import annotations

import unicodeddata
from typing import Any, Dict, List, Union

JsonLike = Union[Dict[str, Any], List[Any], str, int, float, bool, None]


def normalize_nfkc(text: str) -> str:
    return unicodedata.normalize("NFKC", text)


def sanitize_json_like(obj: JsonLike) -> JsonLike:
    if isinstance(obj, str):
        return normalize_nfkc(obj)

    if isinstance(obj, list):
        return [sanitize_json_like(x) for x in obj]

    if isinstance(obj, dict):
        return {str(k): sanitize_json_like(v) for k, v in obj.items()}

    # primitives passthrough
    return obj
