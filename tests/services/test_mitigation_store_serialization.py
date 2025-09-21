from __future__ import annotations

import json
from typing import Dict, Tuple

import pytest

from app.services import mitigation_store


@pytest.fixture(autouse=True)
def reset_store(monkeypatch, tmp_path):
    monkeypatch.setenv("MITIGATION_STORE_BACKEND", "file")
    monkeypatch.setenv("MITIGATION_STORE_FILE", str(tmp_path / "modes.json"))
    monkeypatch.delenv("REDIS_URL", raising=False)
    mitigation_store.reset_for_tests()
    yield
    mitigation_store.reset_for_tests()


def _read_file(path: str) -> Dict[Tuple[str, str], str]:
    with open(path, "r", encoding="utf-8") as handle:
        raw = json.load(handle)
    data: Dict[Tuple[str, str], str] = {}
    for key, value in raw.items():
        if "|" not in key:
            continue
        tenant_key, bot_key = key.split("|", 1)
        tenant = mitigation_store._decode_component(tenant_key) or tenant_key
        bot = mitigation_store._decode_component(bot_key) or bot_key
        data[(tenant, bot)] = value
    return data


def test_file_backend_handles_delimiters(tmp_path):
    mitigation_store.set_mode("ten|ant", "bo|t", "block")
    mitigation_store.set_mode("tenant:colon", "bot:colon", "clarify")

    assert mitigation_store.get_mode("ten|ant", "bo|t") == "block"
    assert mitigation_store.get_mode("tenant:colon", "bot:colon") == "clarify"

    modes = mitigation_store.list_modes()
    assert {("ten|ant", "bo|t"), ("tenant:colon", "bot:colon")} <= {
        (entry["tenant"], entry["bot"]) for entry in modes
    }

    path = tmp_path / "modes.json"
    stored = _read_file(str(path))
    assert stored == {
        ("ten|ant", "bo|t"): "block",
        ("tenant:colon", "bot:colon"): "clarify",
    }


def test_redis_key_round_trip():
    key = mitigation_store._redis_key("ten|ant", "bot:one")
    _, _, tenant_key, bot_key = key.split(":", 3)
    tenant = mitigation_store._decode_component(tenant_key)
    bot = mitigation_store._decode_component(bot_key)
    assert tenant == "ten|ant"
    assert bot == "bot:one"
