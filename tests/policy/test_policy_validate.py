from fastapi import FastAPI
from fastapi.testclient import TestClient


def _app() -> FastAPI:
    app = FastAPI()
    from app.routes.admin_policy_validate import router as r

    app.include_router(r)
    return app


def post(client: TestClient, txt: str):
    return client.post("/admin/api/policy/validate", json={"yaml": txt})


def test_empty_fails() -> None:
    with TestClient(_app()) as client:
        response = post(client, "")
        assert response.status_code == 422
        data = response.json()
        assert data["status"] == "fail"


def test_minimal_ok_with_warnings() -> None:
    with TestClient(_app()) as client:
        txt = "rules:\n  redact: []\n"
        response = post(client, txt)
        assert response.status_code == 200
        assert response.json()["status"] == "ok"


def test_invalid_regex_is_error() -> None:
    with TestClient(_app()) as client:
        txt = """
policy_version: v1
rules:
  redact:
    - id: email
      pattern: '([a-z]+@[a-z]+\\.com('  # missing )
"""
        response = post(client, txt)
        assert response.status_code == 422
        data = response.json()
        assert data["status"] == "fail"
        assert any(i["code"] == "schema.redact.pattern.invalid" for i in data["issues"])


def test_duplicate_ids_flagged() -> None:
    with TestClient(_app()) as client:
        txt = """
rules:
  redact:
    - id: x
      pattern: "foo"
    - id: x
      pattern: "bar"
"""
        response = post(client, txt)
        assert response.status_code == 422
        assert any(i["code"] == "schema.redact.id.dup" for i in response.json()["issues"])
