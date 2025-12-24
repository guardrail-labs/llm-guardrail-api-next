from __future__ import annotations

import re
from typing import Dict, List, Mapping, Tuple

_TOKEN_RE = re.compile(r"[a-z0-9]+")

_LAYER1_KEYWORDS: Dict[str, Dict[str, Tuple[str, ...]]] = {
    "violence_harm": {
        "tokens": (
            "kill",
            "murder",
            "assassinate",
            "poison",
            "ricin",
            "cyanide",
            "fentanyl",
            "detonator",
        ),
        "phrases": (
            "make a bomb",
            "build a bomb",
            "how to make a bomb",
            "how to build a bomb",
            "how to kill",
            "kill someone",
            "poison someone",
            "homemade explosive",
            "build an explosive",
            "make an explosive",
        ),
    },
    "concealment_evasion": {
        "tokens": (
            "alibi",
            "undetected",
            "coverup",
        ),
        "phrases": (
            "leave no trace",
            "no trace",
            "cover my tracks",
            "clean up evidence",
            "wipe fingerprints",
            "destroy evidence",
            "hide evidence",
            "dispose of a body",
            "get rid of evidence",
        ),
    },
    "illicit_markets": {
        "tokens": (
            "darkweb",
            "darknet",
            "escrow",
            "onion",
        ),
        "phrases": (
            "dark web",
            "darknet market",
            "tor marketplace",
            "tor market",
            "onion marketplace",
            "onion site",
            "vendor list",
            "escrow service",
        ),
    },
    "credentials_secrets": {
        "tokens": (
            "password",
            "credential",
            "credentials",
            "apikey",
            "token",
            "secret",
        ),
        "phrases": (
            "api key",
            "api token",
            "access token",
            "bearer token",
            "client secret",
            "secret key",
            "private key",
            "login credentials",
            "database credentials",
            "password reset",
            "password dump",
        ),
    },
}

_MISSPELLINGS: Mapping[str, str] = {
    "passwrod": "password",
    "tokne": "token",
    "credntial": "credential",
    "apikay": "apikey",
}

_TOKEN_EXCLUSIONS: Dict[str, Tuple[str, ...]] = {
    "token": ("token economy",),
    "password": ("password policy", "password policy training"),
}


def layer1_keyword_hits(normalized_text: str) -> Dict[str, List[str]]:
    tokens = _tokenize(normalized_text)
    tokens = [_MISSPELLINGS.get(token, token) for token in tokens]
    token_set = set(tokens)
    padded = f" {normalized_text} " if normalized_text else " "

    hits: Dict[str, List[str]] = {}
    for category in sorted(_LAYER1_KEYWORDS.keys()):
        rules = _LAYER1_KEYWORDS[category]
        matched: set[str] = set()

        for phrase in rules.get("phrases", ()):
            phrase_norm = phrase.lower()
            if f" {phrase_norm} " in padded:
                matched.add(phrase_norm)

        for token in rules.get("tokens", ()):
            token_norm = token.lower()
            if token_norm in token_set and not _token_excluded(token_norm, padded):
                matched.add(token_norm)

        if matched:
            hits[category] = sorted(matched)

    return hits


def layer1_keyword_decisions(normalized_text: str) -> List[Dict[str, object]]:
    hits = layer1_keyword_hits(normalized_text)
    decisions: List[Dict[str, object]] = []
    for category in sorted(hits.keys()):
        decisions.append(
            {
                "source": "layer1_keywords",
                "category": category,
                "matched": hits[category],
            }
        )
    return decisions


def _tokenize(text: str) -> List[str]:
    return _TOKEN_RE.findall(text or "")


def _token_excluded(token: str, padded_text: str) -> bool:
    exclusions = _TOKEN_EXCLUSIONS.get(token)
    if not exclusions:
        return False
    return any(f" {phrase} " in padded_text for phrase in exclusions)


__all__ = ["layer1_keyword_decisions", "layer1_keyword_hits"]
