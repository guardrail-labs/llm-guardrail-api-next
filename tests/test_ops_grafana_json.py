from __future__ import annotations

import json
from pathlib import Path


def test_dashboards_json_loads() -> None:
    for path in Path("ops/grafana/dashboards").glob("*.json"):
        json.loads(path.read_text(encoding="utf-8"))


def test_alerts_json_loads() -> None:
    for path in Path("ops/grafana/alerts").glob("*.json"):
        json.loads(path.read_text(encoding="utf-8"))
