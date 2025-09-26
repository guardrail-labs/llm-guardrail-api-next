from __future__ import annotations

import time
from collections import deque
from typing import Deque, Dict, Iterable, List

DEFAULT_RATE_WINDOW_SECS = 30.0
DEFAULT_MAX_REQS_PER_WINDOW = 20
MIN_TEXT_LEN_FOR_SIM = 24


def _flatten_strings(obj: object, out: List[str]) -> None:
    if isinstance(obj, dict):
        for v in obj.values():
            _flatten_strings(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _flatten_strings(v, out)
    elif isinstance(obj, str):
        out.append(obj)


def collect_strings(obj: object) -> List[str]:
    out: List[str] = []
    _flatten_strings(obj, out)
    return out


def _char_ngrams(s: str, n: int = 3) -> List[str]:
    s = s.casefold()
    if len(s) < n:
        return []
    return [s[i : i + n] for i in range(len(s) - n + 1)]


def jaccard_similarity(a: str, b: str, n: int = 3) -> float:
    A = set(_char_ngrams(a, n))
    B = set(_char_ngrams(b, n))
    if not A and not B:
        return 0.0
    inter = len(A & B)
    union = len(A | B) or 1
    return float(inter) / float(union)


class RollingRate:
    def __init__(self) -> None:
        self._bins: Dict[str, Deque[float]] = {}

    def hit(
        self,
        key: str,
        now: float | None = None,
        window_secs: float = DEFAULT_RATE_WINDOW_SECS,
    ) -> int:
        now = now or time.time()
        q = self._bins.get(key)
        if q is None:
            q = deque()
            self._bins[key] = q
        q.append(now)
        cutoff = now - window_secs
        while q and q[0] < cutoff:
            q.popleft()
        return len(q)

    def size(self, key: str) -> int:
        q = self._bins.get(key)
        return len(q) if q else 0


_rate_store = RollingRate()


def rate_store() -> RollingRate:
    return _rate_store


_LEAKAGE_HINTS = [
    "training data",
    "internal document",
    "admin password",
    "api_key",
    "secret token",
    "private key",
    "system prompt",
    "developer message",
    "ignore previous",
    "hidden instructions",
]


def count_leakage_hints(texts: Iterable[str]) -> int:
    c = 0
    for t in texts:
        low = t.casefold()
        for h in _LEAKAGE_HINTS:
            if h in low:
                c += 1
    return c
