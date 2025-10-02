from typing import Iterable

import pytest

from app import settings as settings_module
from app.settings import Settings, get_settings


_IDEMP_ENV_VARS: Iterable[str] = (
    "APP_ENV",
    "IDEMPOTENCY_MODE",
    "IDEMPOTENCY_LOCK_TTL_S",
    "IDEMPOTENCY_STRICT_FAIL_CLOSED",
)


def _reset_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in _IDEMP_ENV_VARS:
        monkeypatch.delenv(key, raising=False)
    base = get_settings(env="test")
    settings_module.settings = base
    settings_module.IDEMP_METHODS = tuple(sorted(base.idempotency.enforce_methods))
    settings_module.IDEMP_TTL_SECONDS = base.idempotency.lock_ttl_s


def _effective(
    monkeypatch: pytest.MonkeyPatch, env: str, **overrides: str
) -> Settings:
    _reset_settings(monkeypatch)
    monkeypatch.setenv("APP_ENV", env)
    for key, value in overrides.items():
        monkeypatch.setenv(key, value)
    effective = get_settings(env=env)
    settings_module.settings = effective
    settings_module.IDEMP_METHODS = tuple(sorted(effective.idempotency.enforce_methods))
    settings_module.IDEMP_TTL_SECONDS = effective.idempotency.lock_ttl_s
    return effective


def test_dev_defaults_to_observe(monkeypatch: pytest.MonkeyPatch) -> None:
    eff = _effective(monkeypatch, "dev")
    assert eff.idempotency.mode == "observe"
    assert eff.idempotency.lock_ttl_s == 30
    assert eff.idempotency.strict_fail_closed is False


def test_stage_defaults_observe_and_allows_enforce(monkeypatch: pytest.MonkeyPatch) -> None:
    eff = _effective(monkeypatch, "stage")
    assert eff.idempotency.mode == "observe"
    assert eff.idempotency.lock_ttl_s >= 60
    enforced = _effective(monkeypatch, "stage", IDEMPOTENC_
