from __future__ import annotations

from typing import Dict, Iterable, List, Set

from app.tokenization.provider import tokenize


def _norm(s: str) -> str:
    return "".join(ch for ch in s.casefold() if ch.isalnum())


def _window_hits(tokens: List[str], terms: Set[str]) -> Dict[str, int]:
    """
    Slide over token sequences; join consecutive tokens (no separator)
    and check for exact term matches after casefold.

    To bound cost, we only join up to a length close to the longest term.
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
        piece = ""
        for j in range(i, n):
            piece += tokens[j]
            if len(piece) > max_len:
                break
            norm_piece = _norm(piece)
            if norm_piece in tnorm_to_orig:
                for orig in tnorm_to_orig[norm_piece]:
                    hits[orig] += 1
    # Drop zero entries
    return {k: v for k, v in hits.items() if v > 0}


def find_terms_tokenized(text: str, terms: Iterable[str]) -> Dict[str, int]:
    toks = tokenize(text)
    return _window_hits(toks, set(terms))
