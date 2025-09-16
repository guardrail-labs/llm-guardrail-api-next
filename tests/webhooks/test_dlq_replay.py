from __future__ import annotations

import importlib
import json
import os
import time
from pathlib import Path
from typing import Any

import httpx
from starlette.testclient import TestClient

from app.main import create_app
from app.routes import admin_ui
from app.services.config_store import reset_config, set_config


class _MockResp:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


def _write_dlq(path: Path) -> None:
    ev1 = {"ts": 1, "reason": "5xx", "event": {"incident_id": "a"}}
    ev2 = {"ts": 2, "reason": "timeout", "event": {"incident_id": "b"}}
    junk = "not json\n"
    with path.open("w", encoding="utf-8") as handle:
        handle.write(json.dumps(ev1) + "\n")
        handle.write(json.dumps(ev2) + "\n")
        handle.write(junk)


def test_dlq_replay_roundtrip(tmp_path, monkeypatch) -> None:
    dlq_path = tmp_path / "webhook_dlq.jsonl"
    monkeypatch.setenv("WEBHOOK_DLQ_PATH", str(dlq_path))
    monkeypatch.setenv("ADMIN_UI_TOKEN", "admintoken")
    monkeypatch.setenv("ADMIN_UI_SECRET", "csrf-secret")

    wh_module = importlib.import_module("app.services.webhooks")
    wh_module = importlib.reload(wh_module)
    wh_module.configure(reset=True)

    reset_config()
    try:
        set_config(
            {
                "webhook_enable": True,
                "webhook_url": "https://example.com/hook",
                "webhook_secret": "s",
                "webhook_allow_insecure_tls": True,
                "webhook_allowlist_host": "example.com",
                "webhook_timeout_ms": 50,
                "webhook_max_retries": 1,
                "webhook_backoff_ms": 1,
            }
        )

        _write_dlq(dlq_path)
        assert wh_module.dlq_count() == 3

        real_post = httpx.Client.post

        def fake_post(self, url, *args: Any, **kwargs: Any):  # noqa: ANN001
            if url == "https://example.com/hook":
                return _MockResp(200)
            return real_post(self, url, *args, **kwargs)

        monkeypatch.setattr(httpx.Client, "post", fake_post, raising=True)

        requeued = wh_module.requeue_from_dlq(2)
        assert requeued == 2
        assert wh_module.dlq_count() == 1

        deadline = time.time() + 0.5
        while time.time() < deadline and wh_module.stats().get("processed", 0) < 2:
            time.sleep(0.01)
        assert wh_module.stats().get("processed", 0) >= 2

        app = create_app()
        with TestClient(app) as client:
            metrics_resp = client.get("/metrics")
            assert metrics_resp.status_code == 200
            replay_total = 0.0
            for line in metrics_resp.text.splitlines():
                if not line.startswith("guardrail_webhook_deliveries_total"):
                    continue
                if 'outcome="dlq_replayed"' not in line:
                    continue
                try:
                    replay_total = float(line.split()[-1])
                except Exception:
                    continue
            assert replay_total >= 2.0

            auth_headers = {"Authorization": "Bearer admintoken"}
            dlq_resp = client.get("/admin/webhook/dlq", headers=auth_headers)
            assert dlq_resp.status_code == 200
            assert dlq_resp.json()["count"] == wh_module.dlq_count()

            token = admin_ui._csrf_token()
            client.cookies.set("ui_csrf", token)
            replay_resp = client.post(
                "/admin/webhook/replay",
                headers={
                    **auth_headers,
                    "x-csrf-token": token,
                    "content-type": "application/json",
                },
                json={"limit": 5, "csrf_token": token},
            )
            assert replay_resp.status_code == 200
            assert replay_resp.json()["requeued"] == 0

        assert wh_module.dlq_count() == 1
    finally:
        wh_module.configure(reset=True)
        reset_config()
        if hasattr(wh_module, "_DLQ_PATH"):
            setattr(
                wh_module,
                "_DLQ_PATH",
                os.getenv("WEBHOOK_DLQ_PATH", "var/webhook_deadletter.jsonl"),
            )
