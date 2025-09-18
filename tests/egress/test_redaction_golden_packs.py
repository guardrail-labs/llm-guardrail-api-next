import importlib
import os
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional, cast
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from fastapi.testclient import TestClient


def _make_app() -> FastAPI:
    app = FastAPI()
    from app.middleware.egress_redact import EgressRedactMiddleware

    app.add_middleware(EgressRedactMiddleware)

    @app.get("/demo")
    def demo() -> PlainTextResponse:
        body = (
            "Email a.b+z@example.co.uk phone +1 (415) 555-1234 "
            "SSN 123-45-6789 VISA 4111-1111-1111-1111 "
            "JWT eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvZSIsImlhdCI6MTUxNjIzOTAyMn0."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c "
            "AWS AKIA1234567890ABCD12 token_abcdEFGHijklMNOPqrstUV "
            "OPENAI sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        return PlainTextResponse(body, media_type="text/plain; charset=utf-8")

    return app


@contextmanager
def _install_policy(policy_dict: dict) -> Iterator[None]:
    policy_module = cast(Any, importlib.import_module("app.services.policy"))
    original_get_active_policy: Optional[Any] = getattr(policy_module, "get_active_policy", None)
    original_current_rules_version: Optional[Any] = getattr(
        policy_module, "current_rules_version", None
    )
    original_get: Optional[Any] = getattr(policy_module, "get", None)
    policy_module.get_active_policy = lambda: policy_dict
    policy_module.current_rules_version = lambda: "test"
    policy_module.get = lambda: policy_dict
    try:
        yield
    finally:
        if original_get_active_policy is not None:
            policy_module.get_active_policy = original_get_active_policy
        else:
            delattr(policy_module, "get_active_policy")
        if original_current_rules_version is not None:
            policy_module.current_rules_version = original_current_rules_version
        else:
            delattr(policy_module, "current_rules_version")
        if original_get is not None:
            policy_module.get = original_get
        elif hasattr(policy_module, "get"):
            delattr(policy_module, "get")


def _merged_policy() -> dict:
    import pathlib

    import yaml

    pii = yaml.safe_load(pathlib.Path("policy/packs/pii_redact.yaml").read_text())
    sec = yaml.safe_load(pathlib.Path("policy/packs/secrets_redact.yaml").read_text())
    red: List[Dict[str, Any]] = []
    for data in (pii or {}, sec or {}):
        rules = (data or {}).get("rules") or {}
        red += rules.get("redact") or []
    return {"rules": {"redact": red}}


def test_golden_packs_redact_in_egress() -> None:
    with patch.dict(os.environ, {"EGRESS_REDACT_ENABLED": "1"}):
        with _install_policy(_merged_policy()):
            app = _make_app()
            client = TestClient(app)
            response = client.get("/demo")
            assert response.status_code == 200
            text = response.text

    assert "a.b+z@example.co.uk" not in text
    assert "(415) 555-1234" not in text
    assert "123-45-6789" not in text
    assert "4111-1111-1111-1111" not in text
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in text
    assert "AKIA1234567890ABCD12" not in text
    assert "token_abcdEFGHijklMNOPqrstUV" not in text
    assert "sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" not in text
