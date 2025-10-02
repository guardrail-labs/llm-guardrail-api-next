from typing import Literal

import pytest

from app.settings import Settings, get_settings

_IDEMP_ENV_VARS = [
    "APP_ENV",
    "IDEMPOTENCY_MODE",
    "IDEMPOTENCY_ENFORCE_METHODS",
    "IDEMPOTENCY_EXCLUDE_PATHS",
    "IDEMPOTENCY_LOCK_TTL_S",
    "IDEMPOTENCY_WAIT_BUDGET_MS",
    "IDEMPOTENCY_JITTER_MS",
    "IDEMPOTENCY_REPLAY_WINDOW_S",
    "IDEMPOTENCY_STRICT_FAIL_CLOSED",
    "IDEMPOTENCY_MASK_PREFIX_LEN",
    "IDEMPOTENCY_SHADOW_SAMPLE_RATE",
    "IDEMPOTENCY_STORE_BACKEND",
]


def _reset_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _IDEMP_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    get_settings("test")


def _effective(
    monkeypatch: pytest.MonkeyPatch,
    env: Literal["dev", "stage", "prod", "test"],
    **overrides: str,
) -> Settings:
    _reset_settings(monkeypatch)
    monkeypatch.setenv("APP_ENV", env)
    for key, value in overrides.items():
        monkeypatch.setenv(key, value)
    return get_settings(env)


def test_enforce_methods_csv(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _effective(
        monkeypatch,
        "test",
        IDEMPOTENCY_ENFORCE_METHODS="post, put , patch,",
    )
    assert settings.idempotency.enforce_methods == {"POST", "PUT", "PATCH"}


def test_enforce_methods_json(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _effective(
        monkeypatch,
        "test",
        IDEMPOTENCY_ENFORCE_METHODS='["post", "PATCH"]',
    )
    assert settings.idempotency.enforce_methods == {"POST", "PATCH"}


def test_exclude_paths_json(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _effective(
        monkeypatch,
        "test",
        IDEMPOTENCY_EXCLUDE_PATHS='["/health", " /ready "]',
    )
    assert settings.idempotency.exclude_paths == ["/health", "/ready"]


def test_dev_effective_clamps(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _effective(
        monkeypatch,
        "dev",
        IDEMPOTENCY_LOCK_TTL_S="120",
        IDEMPOTENCY_STRICT_FAIL_CLOSED="1",
    )
    assert settings.idempotency.lock_ttl_s == 30
    assert settings.idempotency.strict_fail_closed is False


def test_stage_effective_minimum(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _effective(
        monkeypatch,
        "stage",
        IDEMPOTENCY_LOCK_TTL_S="10",
    )
    assert settings.idempotency.lock_ttl_s == 60


def test_prod_effective_enforces(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _effective(
        monkeypatch,
        "prod",
        IDEMPOTENCY_MODE="observe",
        IDEMPOTENCY_LOCK_TTL_S="30",
    )
    assert settings.idempotency.mode == "enforce"
    assert settings.idempotency.lock_ttl_s == 120
