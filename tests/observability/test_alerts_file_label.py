import pathlib


def test_alerts_use_family_label() -> None:
    p = pathlib.Path("observability/alerts/guardrail-rules.yaml")
    s = p.read_text(encoding="utf-8")
    assert 'guardrail_decisions_total{family="block"}' in s

