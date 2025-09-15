import json
from pathlib import Path


def test_dashboard_references_http_status_metric():
    data = json.loads(Path("observability/grafana/guardrail.json").read_text(encoding="utf-8"))
    exprs = " ".join(
        target.get("expr", "")
        for panel in data.get("panels", [])
        for target in panel.get("targets", [])
    )
    assert "guardrail_http_status_total" in exprs
    assert 'status=~"5.."' in exprs or 'status="429"' in exprs
