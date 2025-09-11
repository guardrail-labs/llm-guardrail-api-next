import importlib
import os
import tempfile
import time
from pathlib import Path

from fastapi.testclient import TestClient


def _make_client():
    os.environ["API_KEY"] = "unit-test-key"
    os.environ["ADMIN_TOKEN"] = "test-token"

    import app.config as cfg

    importlib.reload(cfg)
    import app.main as main

    importlib.reload(main)

    return TestClient(main.build_app())


def _write_rules(path: Path, version: str) -> None:
    path.write_text(f"version: {version}\n", encoding="utf-8")
    # Ensure mtime changes across fast filesystems
    now = time.time()
    os.utime(path, (now, now))


def test_autoreload_picks_up_changes():
    with tempfile.TemporaryDirectory() as tmp:
        rules_path = Path(tmp) / "rules.yaml"
        _write_rules(rules_path, "9")

        os.environ["POLICY_RULES_PATH"] = str(rules_path)
        os.environ["POLICY_AUTORELOAD"] = "true"

        client = _make_client()
        r1 = client.post(
            "/guardrail",
            json={"prompt": "hello"},
            headers={"X-API-Key": "unit-test-key"},
        )
        assert r1.status_code == 200
        assert r1.json()["policy_version"] == "9"

        # Modify file to version 10; autoreload should pick it up automatically
        time.sleep(0.01)  # help ensure distinct mtime on some FS
        _write_rules(rules_path, "10")

        r2 = client.post(
            "/guardrail",
            json={"prompt": "hello again"},
            headers={"X-API-Key": "unit-test-key"},
        )
        assert r2.status_code == 200
        assert r2.json()["policy_version"] == "10"


def test_manual_reload_endpoint_when_autoreload_off():
    with tempfile.TemporaryDirectory() as tmp:
        rules_path = Path(tmp) / "rules.yaml"
        _write_rules(rules_path, "1")

        os.environ["POLICY_RULES_PATH"] = str(rules_path)
        os.environ["POLICY_AUTORELOAD"] = "false"

        client = _make_client()

        # First read -> v1
        r1 = client.post("/guardrail", json={"prompt": "x"}, headers={"X-API-Key": "unit-test-key"})
        assert r1.status_code == 200
        assert r1.json()["policy_version"] == "1"

        # Update file to v2; without autoreload, version should remain v1
        time.sleep(0.01)
        _write_rules(rules_path, "2")

        r2 = client.post("/guardrail", json={"prompt": "y"}, headers={"X-API-Key": "unit-test-key"})
        assert r2.status_code == 200
        assert r2.json()["policy_version"] == "1"

        # Force reload via admin endpoint -> now v2
        r3 = client.post(
            "/admin/policy/reload", headers={"Authorization": "Bearer test-token"}
        )
        assert r3.status_code == 200
        assert r3.json()["ok"] is True
        assert r3.json()["version"] == "2"

        r4 = client.post("/guardrail", json={"prompt": "z"}, headers={"X-API-Key": "unit-test-key"})
        assert r4.status_code == 200
        assert r4.json()["policy_version"] == "2"
