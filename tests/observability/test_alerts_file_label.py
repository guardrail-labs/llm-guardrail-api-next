import pathlib
import re


def test_alerts_use_family_deny_and_no_duplicate_expr():
    p = pathlib.Path("observability/alerts/guardrail-rules.yaml")
    s = p.read_text(encoding="utf-8")
    assert 'guardrail_decisions_total{family="deny"}' in s, 'Alert should filter on family="deny"'
    # No duplicate 'expr:' lines in the deny-rate rule block
    block = re.findall(
        r"- alert:\s*GuardrailBlockRateHigh(.+?)(?:\n\s*-\s*alert:|\Z)",
        s,
        flags=re.S,
    )
    assert block, "Could not find GuardrailBlockRateHigh rule block"
    expr_count = len(re.findall(r"\n\s*expr:", block[0]))
    assert (
        expr_count == 1
    ), f"Expected exactly one expr in GuardrailBlockRateHigh, found {expr_count}"
