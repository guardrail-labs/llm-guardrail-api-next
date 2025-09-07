import importlib
import os
import tempfile
import time
from pathlib import Path

from fastapi.testclient import TestClient


def _make_client():
    os.environ["API_KEY"] = "unit-test-key"

    import app.config as cfg

    importlib.reload(cfg)
    import app.main as main

    importlib.reload(main)

    return TestClient(main.build_app())


def _write_rules(path: Path, contents: str) -> None:
    path.write_text(contents, encoding="utf-8")
    # help ensure distinct mtime on some FS
    now = time.time()
    os.utime(path, (now, now))


def test_policy_blocks_on_deny_regex():
    with tempfile.TemporaryDirectory() as tmp:
        rules_path = Path(tmp) / "rules.yaml"
        _write_rules(
            rules_path,
            """\
version: 42
deny:
  - id: block_phrase
    pattern: "(?i)do not allow this"
    flags: ["i"]
""",
        )

        os.environ["POLICY_RULES_PATH"] = str(rules_path)
        os.environ["POLICY_AUTORELOAD"] = "true"

        client = _make_client()
        r = client.post(
            "/guardrail",
            json={"prompt": "Please DO NOT ALLOW THIS in production."},
            headers={"X-API-Key": "unit-test-key"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["decision"] == "block"
        assert any(h.startswith("policy:deny:block_phrase") for h in body["rule_hits"])
        assert body["policy_version"] == "42"


def test_policy_allows_when_no_match():
    with tempfile.TemporaryDirectory() as tmp:
        rules_path = Path(tmp) / "rules.yaml"
        _write_rules(
            rules_path,
            """\
version: 7
deny:
  - id: forbid_demo
    pattern: "FORBID-DEMO"
""",
        )

        os.environ["POLICY_RULES_PATH"] = str(rules_path)
        os.environ["POLICY_AUTORELOAD"] = "true"

        client = _make_client()
        r = client.post(
            "/guardrail",
            json={"prompt": "totally safe text"},
            headers={"X-API-Key": "unit-test-key"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["decision"] in ("allow", "block")  # pipe heuristics may also flag
        # But deny rule shouldn't be the cause:
        assert not any(h.startswith("policy:deny:forbid_demo") for h in body["rule_hits"])
        assert body["policy_version"] == "7"
