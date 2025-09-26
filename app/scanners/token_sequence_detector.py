from __future__ import annotations

from typing import Dict, Iterable, List, Set

from app.tokenization.provider import tokenize


def _norm(s: str) -> str:
    return "".join(ch for ch in s.casefold() if ch.isalnum())


def _window_hits(tokens: List[str], terms: Set[str]) -> Dict[str, int]:
    """
    Slide over token sequences; join consecutive tokens (no separator)
    and check for exact term matches after casefold.

    The search window is bounded using the canonical (normalized) length so
    punctuation or whitespace inside the tokens does not prematurely stop the
    scan.
    """
    if not tokens or not terms:
        return {}

    terms_norm: Dict[str, str] = {}
    tnorm_to_orig: Dict[str, List[str]] = {}
    for term in terms:
        norm = _norm(term)
        if not norm:
            continue
        terms_norm[term] = norm
        tnorm_to_orig.setdefault(norm, []).append(term)

    if not terms_norm:
        return {}

    max_len = max(len(v) for v in terms_norm.values())

    hits: Dict[str, int] = {t: 0 for t in terms_norm}

    n = len(tokens)
    for i in range(n):
        piece_norm = ""
        for j in range(i, n):
            piece_norm += _norm(tokens[j])

            if len(piece_norm) > max_len:
                break

            if piece_norm in tnorm_to_orig:
                for orig in tnorm_to_orig[piece_norm]:
                    hits[orig] += 1
    # Drop zero entries
    return {k: v for k, v in hits.items() if v > 0}


def find_terms_tokenized(text: str, terms: Iterable[str]) -> Dict[str, int]:
    toks = tokenize(text)
    return _window_hits(toks, set(terms))
