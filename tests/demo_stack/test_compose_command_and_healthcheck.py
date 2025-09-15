from pathlib import Path

import yaml


def test_compose_uses_correct_uvicorn_target_and_healthcheck():
    p = Path("docker-compose.yml")
    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    svc = data["services"]["guardrail-api"]
    cmd = svc.get("command")
    assert "app.main:create_app" in cmd, (
        f"Expected app.main:create_app in command, got: {cmd}"
    )
    hc = svc.get("healthcheck", {})
    test = hc.get("test", [])
    test_str = " ".join(test) if isinstance(test, list) else str(test)
    assert ("curl" in test_str) or ("python" in test_str), (
        f"Healthcheck should use curl or python, got: {test_str}"
    )
