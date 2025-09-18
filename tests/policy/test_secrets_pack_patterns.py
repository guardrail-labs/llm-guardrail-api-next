from __future__ import annotations

import re
from pathlib import Path

import yaml

PACK = Path("policy/packs/secrets_redact.yaml")
CORPUS = Path("tests/policy/corpus/secrets.yaml")


def _load_patterns() -> list[tuple[str | None, re.Pattern[str]]]:
    doc = yaml.safe_load(PACK.read_text(encoding="utf-8"))
    rules = ((doc or {}).get("rules") or {}).get("redact") or []
    compiled: list[tuple[str | None, re.Pattern[str]]] = []
    for rule in rules:
        pattern = rule.get("pattern")
        rule_id = rule.get("id")
        assert isinstance(pattern, str) and pattern.strip(), f"bad pattern for {rule_id}"
        try:
            compiled.append((rule_id, re.compile(pattern)))
        except re.error as exc:  # pragma: no cover - sanity
            raise AssertionError(f"regex compile failed for {rule_id}: {exc}") from exc
    return compiled


def _load_corpus() -> dict[str, list[str]]:
    return yaml.safe_load(CORPUS.read_text(encoding="utf-8")) or {}


def test_corpus_positive_matches() -> None:
    patterns = _load_patterns()
    corpus = _load_corpus()
    hits = 0
    for sample in corpus.get("positive", []):
        matched = any(regex.search(sample) for _, regex in patterns)
        assert matched, f"expected a match for: {sample}"
        hits += 1
    assert hits > 0


def test_corpus_negative_not_matched() -> None:
    patterns = _load_patterns()
    corpus = _load_corpus()
    for sample in corpus.get("negative", []):
        matched = any(regex.search(sample) for _, regex in patterns)
        assert not matched, f"unexpected match for: {sample}"
