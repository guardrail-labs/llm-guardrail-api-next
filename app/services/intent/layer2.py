from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from app import settings

_MAX_TYPO_TOKEN_LENGTH = 16
_MAX_TYPO_COMPARISONS = 256


@dataclass(frozen=True)
class Layer2Config:
    enabled: bool = True
    bucket_vocab: Dict[str, List[str]] = field(default_factory=dict)
    pair_weights: Dict[str, float] = field(default_factory=dict)
    typo_sensitive_tokens: List[str] = field(default_factory=list)
    typo_min_ratio: float = 0.85
    score_scale: float = 1.0
    max_score: int = 100

    @classmethod
    def from_settings(cls) -> "Layer2Config":
        return cls(
            enabled=settings.LAYER2_INTENT_ENABLED,
            bucket_vocab={
                bucket: list(terms) for bucket, terms in settings.LAYER2_BUCKET_VOCAB.items()
            },
            pair_weights=dict(settings.LAYER2_PAIR_WEIGHTS),
            typo_sensitive_tokens=list(settings.LAYER2_TYPO_SENSITIVE_TOKENS),
            typo_min_ratio=settings.LAYER2_TYPO_MIN_RATIO,
            score_scale=settings.LAYER2_SCORE_SCALE,
            max_score=settings.LAYER2_MAX_SCORE,
        )


@dataclass(frozen=True)
class Layer2Result:
    score: int
    bucket_hits: Dict[str, int]
    pair_hits: List[str]
    typo_hits: List[str]
    signals: List[str]


def score_intent(text: str, cfg: Layer2Config) -> Layer2Result:
    normalized = _normalize_text(text)
    tokens = _tokenize(normalized)
    token_counts = Counter(tokens)

    bucket_hits: Dict[str, int] = {}
    typo_hits: List[str] = []

    bucket_token_map = _bucket_token_map(cfg.bucket_vocab)

    for bucket, vocab in cfg.bucket_vocab.items():
        hit_count = 0
        for term in vocab:
            term_norm = term.lower()
            if " " in term_norm:
                hit_count += _count_phrase(normalized, term_norm)
            else:
                hit_count += token_counts.get(term_norm, 0)
        if hit_count:
            bucket_hits[bucket] = hit_count

    typo_hits = _typo_matches(tokens, cfg, bucket_hits, bucket_token_map)

    pair_hits, raw_score = _apply_pair_weights(bucket_hits, cfg.pair_weights)
    score = min(cfg.max_score, int(round(raw_score * cfg.score_scale)))

    signals = _build_signals(bucket_hits, pair_hits, typo_hits)

    return Layer2Result(
        score=score,
        bucket_hits=bucket_hits,
        pair_hits=pair_hits,
        typo_hits=typo_hits,
        signals=signals,
    )


def _normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower()).strip()


def _tokenize(text: str) -> List[str]:
    return re.findall(r"[a-z0-9]+", text)


def _count_phrase(text: str, phrase: str) -> int:
    pattern = r"\b" + re.escape(phrase) + r"\b"
    return len(re.findall(pattern, text))


def _bucket_token_map(bucket_vocab: Dict[str, List[str]]) -> Dict[str, str]:
    mapping: Dict[str, str] = {}
    for bucket, terms in bucket_vocab.items():
        for term in terms:
            term_norm = term.lower()
            if " " in term_norm:
                continue
            mapping[term_norm] = bucket
    return mapping


def _typo_matches(
    tokens: List[str],
    cfg: Layer2Config,
    bucket_hits: Dict[str, int],
    bucket_token_map: Dict[str, str],
) -> List[str]:
    typo_hits: List[str] = []
    sensitive = [token.lower() for token in cfg.typo_sensitive_tokens]
    sensitive_set = set(sensitive)

    comparisons = 0
    seen: set[str] = set()
    for token in tokens:
        if token in seen:
            continue
        seen.add(token)
        if token in sensitive_set:
            continue
        if len(token) > _MAX_TYPO_TOKEN_LENGTH:
            continue
        for target in sensitive:
            if comparisons >= _MAX_TYPO_COMPARISONS:
                return typo_hits
            comparisons += 1
            if token == target:
                continue
            distance = _edit_distance(token, target)
            max_len = max(len(token), len(target)) or 1
            ratio = 1 - (distance / max_len)
            if distance <= 1 or ratio >= cfg.typo_min_ratio:
                typo_hits.append(f"{token}->{target}")
                bucket = bucket_token_map.get(target)
                if bucket:
                    bucket_hits[bucket] = bucket_hits.get(bucket, 0) + 1
                break
    return typo_hits


def _edit_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    rows = len(a) + 1
    cols = len(b) + 1
    prev = list(range(cols))
    for i in range(1, rows):
        curr = [i]
        for j in range(1, cols):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            curr.append(
                min(
                    prev[j] + 1,
                    curr[j - 1] + 1,
                    prev[j - 1] + cost,
                )
            )
        prev = curr
    return prev[-1]


def _apply_pair_weights(
    bucket_hits: Dict[str, int], pair_weights: Dict[str, float]
) -> Tuple[List[str], float]:
    pair_hits: List[str] = []
    score = 0.0
    for pair_key in sorted(pair_weights.keys()):
        left, right = pair_key.split("|", 1)
        if bucket_hits.get(left, 0) > 0 and bucket_hits.get(right, 0) > 0:
            pair_hits.append(pair_key)
            score += pair_weights[pair_key]
    return pair_hits, score


def _build_signals(
    bucket_hits: Dict[str, int],
    pair_hits: List[str],
    typo_hits: List[str],
) -> List[str]:
    signals: List[str] = []
    for bucket in sorted(bucket_hits.keys()):
        signals.append(f"bucket:{bucket}")
    for pair in sorted(pair_hits):
        signals.append(f"pair:{pair}")
    for typo in sorted(typo_hits):
        signals.append(f"typo:{typo}")
    return signals
