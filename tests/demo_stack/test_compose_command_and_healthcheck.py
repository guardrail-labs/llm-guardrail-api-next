from pathlib import Path

import yaml


def test_compose_uvicorn_target_and_healthcheck():
    data = yaml.safe_load(Path("docker-compose.yml").read_text(encoding="utf-8"))
    svc = data["services"]["guardrail-api"]
    assert "app.main:create_app" in svc.get("command", "")
    healthcheck = svc.get("healthcheck", {})
    check_cmd = healthcheck.get("test", [])
    if isinstance(check_cmd, list):
        check_str = " ".join(str(part) for part in check_cmd)
    else:
        check_str = str(check_cmd)
    assert "curl" in check_str or "python" in check_str
