import json
from pathlib import Path

from app.services.detectors import evaluate_prompt
from app.services.text.normalize import normalize_for_matching

FIXTURES_PATH = Path(__file__).resolve().parent / "fixtures" / "layer1_prompts.json"


def _load_prompts() -> dict[str, str]:
    return json.loads(FIXTURES_PATH.read_text(encoding="utf-8"))


def _layer1_by_category(result: dict) -> dict[str, dict]:
    decisions = [d for d in result.get("decisions", []) if d.get("source") == "layer1_keywords"]
    return {d["category"]: d for d in decisions}


def test_normalize_for_matching_collapses_punctuation() -> None:
    text = '  API-Key:\t"ABC-123"  '
    assert normalize_for_matching(text) == "api key abc 123"


def test_layer1_triggers_for_expanded_keywords() -> None:
    prompts = _load_prompts()
    result = evaluate_prompt(prompts["violence_concealment"])
    layer1 = _layer1_by_category(result)

    assert "violence_harm" in layer1
    assert "concealment_evasion" in layer1
    assert "make a bomb" in layer1["violence_harm"]["matched"]
    assert "leave no trace" in layer1["concealment_evasion"]["matched"]


def test_layer1_triggers_illicit_markets() -> None:
    prompts = _load_prompts()
    result = evaluate_prompt(prompts["illicit_markets"])
    layer1 = _layer1_by_category(result)

    assert "illicit_markets" in layer1
    assert "dark web" in layer1["illicit_markets"]["matched"]
    assert "vendor list" in layer1["illicit_markets"]["matched"]


def test_layer1_typo_mapping_triggers_credentials() -> None:
    prompts = _load_prompts()
    result = evaluate_prompt(prompts["secrets_typo"])
    layer1 = _layer1_by_category(result)

    assert "credentials_secrets" in layer1
    matched = layer1["credentials_secrets"]["matched"]
    assert "password" in matched
    assert "apikey" in matched


def test_layer1_neutral_prompts_do_not_trigger() -> None:
    prompts = _load_prompts()

    for key in ("neutral_token", "neutral_password", "neutral_bomb"):
        result = evaluate_prompt(prompts[key])
        layer1 = _layer1_by_category(result)
        assert not layer1


def test_layer1_metadata_is_deterministic() -> None:
    prompts = _load_prompts()
    result = evaluate_prompt(prompts["secrets_typo_variant"])
    decisions = [d for d in result.get("decisions", []) if d.get("source") == "layer1_keywords"]
    categories = [d["category"] for d in decisions]

    assert categories == sorted(categories)
    for decision in decisions:
        matched = decision["matched"]
        assert matched == sorted(matched)


def test_layer1_token_exclusion_is_occurrence_scoped() -> None:
    prompt = "token economy is a topic. please reset token for my account."
    result = evaluate_prompt(prompt)
    layer1 = _layer1_by_category(result)

    assert "credentials_secrets" in layer1
    assert "token" in layer1["credentials_secrets"]["matched"]


def test_layer1_password_exclusion_is_occurrence_scoped() -> None:
    prompt = "password policy training is required. this leaked password needs to be rotated."
    result = evaluate_prompt(prompt)
    layer1 = _layer1_by_category(result)

    assert "credentials_secrets" in layer1
    assert "password" in layer1["credentials_secrets"]["matched"]


def test_layer1_exclusion_controls() -> None:
    for prompt in ("token economy discussion", "password policy training materials"):
        result = evaluate_prompt(prompt)
        layer1 = _layer1_by_category(result)
        assert not layer1
