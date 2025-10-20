from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import (
    Any,
    Dict,
    Iterable,
    List,
    Literal,
    Mapping,
    Optional,
    Pattern,
    Sequence,
    Tuple,
    TypedDict,
    TypeVar,
    cast,
)

SeverityLevel = Literal["low", "medium", "high"]
AdvisoryLevel = Literal["pass", "flag", "clarify", "block"]


SEVERITY_LEVELS: Tuple[SeverityLevel, ...] = ("low", "medium", "high")
ADVISORY_LEVELS: Tuple[AdvisoryLevel, ...] = (
    "pass",
    "flag",
    "clarify",
    "block",
)


class RuleOverride(TypedDict, total=False):
    advisory: AdvisoryLevel
    severity: SeverityLevel


@dataclass(frozen=True)
class Rule:
    pack: str
    id: str
    title: str
    severity: SeverityLevel
    advisory: AdvisoryLevel
    pattern: Optional[Pattern[str]] = None
    any_terms: Optional[Tuple[str, ...]] = None
    references: Tuple[str, ...] = ()

    def with_override(self, override: RuleOverride) -> "Rule":
        updated = self
        if "advisory" in override:
            advisory = _normalize_level(override["advisory"], ADVISORY_LEVELS)
            updated = replace(updated, advisory=advisory)
        if "severity" in override:
            severity = _normalize_level(override["severity"], SEVERITY_LEVELS)
            updated = replace(updated, severity=severity)
        return updated


@dataclass(frozen=True)
class LoadedPacks:
    rules: Tuple[Rule, ...]

    def by_pack(self) -> Dict[str, Tuple[Rule, ...]]:
        buckets: Dict[str, List[Rule]] = {}
        for rule in self.rules:
            buckets.setdefault(rule.pack, []).append(rule)
        return {k: tuple(v) for k, v in buckets.items()}


def load_packs(
    dirpath: str = "policy/packs",
    tenant_overrides: Optional[Mapping[str, Mapping[str, RuleOverride]]] = None,
) -> LoadedPacks:
    root = Path(dirpath)
    if not root.exists():
        raise FileNotFoundError(f"Policy pack directory not found: {dirpath}")

    overrides = _normalise_overrides(tenant_overrides)
    rules: List[Rule] = []
    for pack_file in sorted(root.glob("*.yaml")):
        data = _yaml_load(pack_file.read_text(encoding="utf-8"))
        if "pack" not in data:
            # Skip legacy pack files that do not follow the new schema.
            continue
        pack_name = _extract_pack_name(data, pack_file.stem)
        _validate_pack_schema(data, source=str(pack_file))
        for raw_rule in data.get("rules", []):
            rule = _compile_rule(pack_name, raw_rule, source=str(pack_file))
            pack_overrides = overrides.get(pack_name, {})
            if rule.id in pack_overrides:
                rule = rule.with_override(pack_overrides[rule.id])
            rules.append(rule)
    return LoadedPacks(rules=tuple(rules))


def _extract_pack_name(data: Mapping[str, Any], fallback: str) -> str:
    name = str(data.get("pack", fallback)).strip()
    if not name:
        raise ValueError("Pack name cannot be empty")
    return name.upper()


def _normalise_overrides(
    tenant_overrides: Optional[Mapping[str, Mapping[str, RuleOverride]]],
) -> Dict[str, Dict[str, RuleOverride]]:
    result: Dict[str, Dict[str, RuleOverride]] = {}
    if not tenant_overrides:
        return result
    for pack_name, overrides in tenant_overrides.items():
        normalised_pack = pack_name.upper()
        pack_entries: Dict[str, RuleOverride] = {}
        for rule_id, override in overrides.items():
            pack_entries[str(rule_id)] = cast(RuleOverride, dict(override))
    result[normalised_pack] = pack_entries
    return result


def _validate_pack_schema(data: Mapping[str, Any], source: str) -> None:
    rules = data.get("rules")
    if rules is None:
        raise ValueError(f"Pack file {source} missing 'rules' array")
    if not isinstance(rules, list):
        raise TypeError(f"Pack file {source} has non-list 'rules'")
    for rule in rules:
        if not isinstance(rule, Mapping):
            raise TypeError(f"Rule entry in {source} must be a mapping")
        if "id" not in rule:
            raise ValueError(f"Rule in {source} missing required 'id'")
        if not isinstance(rule["id"], str):
            raise TypeError(f"Rule id in {source} must be a string")
        if "advisory" in rule:
            _normalize_level(rule["advisory"], ADVISORY_LEVELS)
        if "severity" in rule:
            _normalize_level(rule["severity"], SEVERITY_LEVELS)
        _validate_iterable(rule, "any_terms", source)
        _validate_iterable(rule, "references", source)


def _validate_iterable(rule: Mapping[str, Any], key: str, source: str) -> None:
    if key not in rule:
        return
    value = rule[key]
    if not isinstance(value, Iterable) or isinstance(value, (str, bytes)):
        raise TypeError(f"Field '{key}' in {source} must be a list of strings")
    for item in value:
        if not isinstance(item, str):
            raise TypeError(f"Field '{key}' in {source} must contain strings")


LevelT = TypeVar("LevelT", AdvisoryLevel, SeverityLevel)


def _normalize_level(level: str, allowed: Sequence[LevelT]) -> LevelT:
    normalized = level.lower()
    if normalized not in allowed:
        options = ", ".join(allowed)
        raise ValueError(f"Level '{level}' not in [{options}]")
    return cast(LevelT, normalized)


def _compile_rule(pack: str, raw: Mapping[str, Any], source: str) -> Rule:
    rid = str(raw["id"])
    title = str(raw.get("title", rid))
    severity = _normalize_level(str(raw.get("severity", "medium")), SEVERITY_LEVELS)
    advisory = _normalize_level(str(raw.get("advisory", "flag")), ADVISORY_LEVELS)
    pattern_text = raw.get("pattern")
    compiled: Optional[Pattern[str]] = None
    if pattern_text is not None:
        if not isinstance(pattern_text, str):
            raise TypeError(f"Rule pattern in {source} must be a string")
        try:
            compiled = re.compile(pattern_text, re.IGNORECASE)
        except re.error as exc:
            raise ValueError(
                f"Invalid regex for rule {pack}:{rid} in {source}: {exc}"
            ) from exc
    terms: Optional[Tuple[str, ...]] = None
    if "any_terms" in raw:
        items = tuple(str(term) for term in raw["any_terms"])
        terms = items or None
    references: Tuple[str, ...] = ()
    if "references" in raw:
        references = tuple(str(ref) for ref in raw["references"])
    return Rule(
        pack=pack,
        id=rid,
        title=title,
        severity=severity,
        advisory=advisory,
        pattern=compiled,
        any_terms=terms,
        references=references,
    )


def _yaml_load(text: str) -> Dict[str, Any]:
    try:
        loaded_json = json.loads(text)
        if not isinstance(loaded_json, dict):
            raise TypeError("Top-level JSON structure must be a mapping")
        return loaded_json
    except Exception:
        pass

    try:
        import yaml

        loaded = yaml.safe_load(text)
        if loaded is None:
            return {}
        if not isinstance(loaded, dict):
            raise TypeError("Top-level YAML structure must be a mapping")
        return loaded
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "YAML parsing failed and PyYAML not installed; install pyyaml or "
            "provide JSON."
        ) from exc

