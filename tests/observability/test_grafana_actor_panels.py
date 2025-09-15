import json
from pathlib import Path


def test_grafana_has_actor_panels():
    data = json.loads(Path("observability/grafana/guardrail.json").read_text(encoding="utf-8"))
    panels = data.get("panels", [])
    expr_values = []
    for panel in panels:
        for target in panel.get("targets", []):
            expr = target.get("expr")
            if isinstance(expr, str):
                expr_values.append(expr)
    combined = " ".join(expr_values)
    assert "guardrail_actor_decisions_total" in combined
    assert 'family="deny"' in combined
