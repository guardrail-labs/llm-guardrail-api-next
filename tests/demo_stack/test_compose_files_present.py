import json
from pathlib import Path


def test_compose_and_configs_present_and_valid() -> None:
    assert Path("docker-compose.yml").exists()
    assert Path("docker/prometheus/prometheus.yml").exists()
    assert Path("docker/grafana/provisioning/datasources/datasource.yml").exists()
    assert Path("docker/grafana/provisioning/dashboards/dashboard.yml").exists()
    # Dashboard JSON should parse
    p = Path("observability/grafana/guardrail.json")
    assert p.exists(), "observability/grafana/guardrail.json missing"
    json.loads(p.read_text(encoding="utf-8"))

