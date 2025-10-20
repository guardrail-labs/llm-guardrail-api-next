from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Iterable, List

from app.ingress.multimodal import detect_injection
from app.policy.pack_engine import evaluate_text
from app.policy.packs import load_packs
from app.sanitizers.confusables import analyze_confusables
from app.sanitizers.unicode import sanitize_unicode

_POLICY_PACKS = load_packs("policy/packs")


_INJ = re.compile(
    r"(ignore (all )?previous instructions|override (the )?system prompt|"
    r"disregard (the )?rules|as (system|developer) role|do not sanitize)",
    re.I,
)


@dataclass(frozen=True)
class Example:
    id: str
    cat: str
    text: str
    label: int


def _load_jsonl(path: str) -> List[Example]:
    out: List[Example] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            data = line.strip()
            if not data:
                continue
            payload = json.loads(data)
            out.append(
                Example(
                    id=str(payload["id"]),
                    cat=str(payload["cat"]),
                    text=str(payload["text"]),
                    label=int(payload["label"]),
                )
            )
    return out


def load_corpus(paths: Iterable[str]) -> List[Example]:
    out: List[Example] = []
    for path in paths:
        out.extend(_load_jsonl(path))
    return out


def _predict_injection(text: str) -> int:
    return 1 if _INJ.search(text) else 0


def _predict_unicode(text: str) -> int:
    sanitized = sanitize_unicode(text)
    return 1 if sanitized != text else 0


def _predict_confusable(text: str) -> int:
    report = analyze_confusables(text)
    return 1 if report.confusable_count > 0 else 0


def _predict_policy(text: str) -> int:
    violations, _action = evaluate_text(text, _POLICY_PACKS)
    return 1 if violations else 0


def _predict_image(text: str) -> int:
    hits = detect_injection(text)
    return 1 if hits > 0 else 0


def predict(example: Example) -> int:
    cat = example.cat
    text = example.text

    if cat == "injection":
        return _predict_injection(text)
    if cat == "unicode":
        return _predict_unicode(text)
    if cat == "confusable":
        return _predict_confusable(text)
    if cat == "policy":
        return _predict_policy(text)
    if cat == "image":
        return _predict_image(text)
    return 0
