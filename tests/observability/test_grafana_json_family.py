import json
from pathlib import Path


def test_grafana_panels_group_by_family():
    p = Path("observability/grafana/guardrail.json")
    data = json.loads(p.read_text(encoding="utf-8"))
    panels = data.get("panels", [])
    # Find any target that references guardrail_decisions_total
    exprs = []
    for panel in panels:
        for tgt in panel.get("targets", []):
            e = tgt.get("expr", "")
            if "guardrail_decisions_total" in e:
                exprs.append(e)
    assert exprs, "Dashboard should include queries for guardrail_decisions_total"
    assert any("sum by (family)" in e for e in exprs), "Queries must group by family"
