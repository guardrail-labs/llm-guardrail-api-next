from __future__ import annotations

import importlib
import sys
import types
from typing import Any, Callable, ContextManager

import pytest
from pytest import MonkeyPatch

from app.services.mitigation_prefs import _STORE, set_mode


def _build_sqlalchemy_stub() -> tuple[types.ModuleType, types.ModuleType]:
    sa_module = types.ModuleType("sqlalchemy")

    def _type_factory(*_args: Any, **_kwargs: Any) -> None:
        return None

    class _Column:
        def __init__(self, name: str, *_args: Any, **_kwargs: Any) -> None:
            self.name = name

        def asc(self) -> "_Column":
            return self

        def desc(self) -> "_Column":
            return self

    class _Table:
        def __init__(self, _name: str, _metadata: Any, *columns: _Column) -> None:
            self.c = types.SimpleNamespace(**{col.name: col for col in columns})

    class _MetaData:
        def create_all(self, *_args: Any, **_kwargs: Any) -> None:
            return None

    class _Insert:
        def values(self, *_args: Any, **_kwargs: Any) -> "_Insert":
            return self

    class _Select:
        def where(self, *_args: Any, **_kwargs: Any) -> "_Select":
            return self

        def order_by(self, *_args: Any, **_kwargs: Any) -> "_Select":
            return self

        def offset(self, *_args: Any, **_kwargs: Any) -> "_Select":
            return self

        def limit(self, *_args: Any, **_kwargs: Any) -> "_Select":
            return self

        def select_from(self, *_args: Any, **_kwargs: Any) -> "_Select":
            return self

    class _Result:
        def mappings(self) -> list[Any]:
            return []

        def scalar_one(self) -> int:
            return 0

        @property
        def rowcount(self) -> int:
            return 0

    class _Connection:
        def execute(self, *_args: Any, **_kwargs: Any) -> _Result:
            return _Result()

    class _Engine:
        def begin(self) -> ContextManager[_Connection]:
            class _Ctx:
                def __enter__(self_inner) -> _Connection:
                    return _Connection()

                def __exit__(self_inner, *_exc: Any) -> None:
                    return None

            return _Ctx()

    def _create_engine(*_args: Any, **_kwargs: Any) -> _Engine:
        return _Engine()

    def _index(*_args: Any, **_kwargs: Any) -> None:
        return None

    def _select(*_args: Any, **_kwargs: Any) -> _Select:
        return _Select()

    def _text(*_args: Any, **_kwargs: Any) -> str:
        return ""

    setattr(sa_module, "Column", _Column)
    setattr(sa_module, "DateTime", _type_factory)
    setattr(sa_module, "Index", _index)
    setattr(sa_module, "MetaData", _MetaData)
    setattr(sa_module, "String", _type_factory)
    setattr(sa_module, "Table", _Table)
    setattr(sa_module, "Text", _type_factory)
    setattr(sa_module, "create_engine", _create_engine)
    setattr(sa_module, "insert", lambda *_a, **_kw: _Insert())
    setattr(sa_module, "select", _select)
    setattr(sa_module, "text", _text)

    sql_module = types.ModuleType("sqlalchemy.sql")
    setattr(sql_module, "and_", lambda *args, **_kwargs: tuple(args))

    class _Func:
        def __getattr__(self, _name: str) -> Callable[..., int]:
            return lambda *_args, **_kwargs: 0

    setattr(sql_module, "func", _Func())

    return sa_module, sql_module


def _import_decisions(monkeypatch: MonkeyPatch):
    try:
        return importlib.import_module("app.services.decisions")
    except ModuleNotFoundError as exc:
        if exc.name != "sqlalchemy":
            raise
        sa_module, sql_module = _build_sqlalchemy_stub()
        original_sa = sys.modules.get("sqlalchemy")
        original_sql = sys.modules.get("sqlalchemy.sql")
        original_decisions = sys.modules.pop("app.services.decisions", None)
        monkeypatch.setitem(sys.modules, "sqlalchemy", sa_module)
        monkeypatch.setitem(sys.modules, "sqlalchemy.sql", sql_module)
        module = importlib.import_module("app.services.decisions")
        sys.modules.pop("sqlalchemy", None)
        sys.modules.pop("sqlalchemy.sql", None)
        if original_sa is not None:
            sys.modules["sqlalchemy"] = original_sa
        if original_sql is not None:
            sys.modules["sqlalchemy.sql"] = original_sql
        if original_decisions is not None:
            sys.modules["app.services.decisions"] = original_decisions
        else:
            sys.modules.pop("app.services.decisions", None)
        return module


def setup_function() -> None:
    _STORE.clear()


def test_pipeline_applies_explicit_override(monkeypatch: MonkeyPatch) -> None:
    decisions_mod = _import_decisions(monkeypatch)
    if not hasattr(decisions_mod, "evaluate_and_record"):
        pytest.skip("evaluate_and_record not available")

    def fake_eval(payload: _StubInput) -> _DummyResult:
        assert payload.tenant == "t1"
        assert payload.bot == "b1"
        return _DummyResult("clarify")

    monkeypatch.setattr(decisions_mod, "_evaluate_policy", fake_eval, raising=False)

    set_mode("t1", "b1", "block")

    result = decisions_mod.evaluate_and_record(_StubInput(tenant="t1", bot="b1"))

    assert result.mitigation == "block"


def test_pipeline_respects_force_block(monkeypatch: MonkeyPatch) -> None:
    decisions_mod = _import_decisions(monkeypatch)
    if not hasattr(decisions_mod, "evaluate_and_record"):
        pytest.skip("evaluate_and_record not available")
    if not hasattr(decisions_mod, "is_force_block_enabled_for_tenant"):
        pytest.skip("force block helper not available")

    def fake_eval(payload: _StubInput) -> _DummyResult:
        assert payload.tenant == "t_force"
        return _DummyResult("redact", id_="Y", ts_ms=2)

    monkeypatch.setattr(decisions_mod, "_evaluate_policy", fake_eval, raising=False)

    monkeypatch.setattr(
        decisions_mod,
        "is_force_block_enabled_for_tenant",
        lambda tenant: tenant == "t_force",
    )

    result = decisions_mod.evaluate_and_record(_StubInput(tenant="t_force", bot="any"))

    assert result.mitigation == "block"


class _StubInput:
    def __init__(self, tenant: str, bot: str, content: str = "hello") -> None:
        self.tenant = tenant
        self.bot = bot
        self.content = content


class _DummyResult:
    def __init__(self, mitigation: str, *, id_: str = "X", ts_ms: int = 1) -> None:
        self.mitigation = mitigation
        self.id = id_
        self.ts_ms = ts_ms
