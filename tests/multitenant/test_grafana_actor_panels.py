import json
from pathlib import Path


def test_grafana_has_actor_panels():
    data = json.loads(Path("observability/grafana/guardrail.json").read_text(encoding="utf-8"))
    panels = json.dumps(data.get("panels", []))
    norm = panels.replace('\\"', '"')
    assert "guardrail_actor_decisions_total" in norm
    assert 'family="deny"' in norm
    assert "sum by (tenant)" in norm or "topk(5, sum by (bot)" in norm
