import json
from pathlib import Path

from app.services.intent.layer2 import Layer2Config, score_intent

FIXTURES_PATH = Path(__file__).resolve().parent / "fixtures" / "layer2_prompts.json"


def _load_prompts() -> dict[str, str]:
    return json.loads(FIXTURES_PATH.read_text(encoding="utf-8"))


def test_layer2_cooccurrence_hits():
    prompts = _load_prompts()
    cfg = Layer2Config.from_settings()
    result = score_intent(prompts["violence_concealment"], cfg)

    assert result.bucket_hits.get("violence_harm", 0) > 0
    assert result.bucket_hits.get("concealment_evasion", 0) > 0
    assert "violence_harm|concealment_evasion" in result.pair_hits
    assert 30 <= result.score <= cfg.max_score


def test_layer2_pair_weights_affect_score():
    prompts = _load_prompts()
    cfg = Layer2Config.from_settings()
    result = score_intent(prompts["illicit_market_content"], cfg)

    assert result.bucket_hits.get("illicit_markets", 0) > 0
    assert result.bucket_hits.get("illicit_content", 0) > 0
    assert "illicit_markets|illicit_content" in result.pair_hits
    assert 15 <= result.score <= cfg.max_score


def test_layer2_typo_matching_triggers():
    prompts = _load_prompts()
    cfg = Layer2Config.from_settings()
    result = score_intent(prompts["typo_sensitive"], cfg)

    assert result.typo_hits
    assert result.bucket_hits.get("credentials_secrets", 0) > 0
    assert result.bucket_hits.get("malware_intrusion", 0) > 0
    assert result.score >= 5


def test_layer2_neutral_prompts_low_score():
    prompts = _load_prompts()
    cfg = Layer2Config.from_settings()

    result_password = score_intent(prompts["neutral_password_reset"], cfg)
    result_tech = score_intent(prompts["neutral_tech_question"], cfg)

    assert result_password.score <= 2
    assert result_tech.score == 0


def test_layer2_output_deterministic():
    prompts = _load_prompts()
    cfg = Layer2Config.from_settings()

    first = score_intent(prompts["illicit_market_content"], cfg)
    second = score_intent(prompts["illicit_market_content"], cfg)

    assert first == second
