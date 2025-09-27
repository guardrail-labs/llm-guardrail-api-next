from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable

from starlette.testclient import TestClient

UUID4_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


def _extract_request_id_from_log(rec: Dict[str, Any]) -> str:
    return str(rec.get("request_id") or rec.get("rid") or "")


def _access_log_records(caplog) -> Iterable[Dict[str, Any]]:
    for rec in caplog.records:
        if rec.name != "access":
            continue
        msg: Any = getattr(rec, "msg", "")
        if isinstance(msg, dict):
            yield msg
            continue
        try:
            parsed = json.loads(str(msg))
        except Exception:
            continue
        if isinstance(parsed, dict):
            yield parsed


def test_access_log_matches_client_supplied_request_id(client: TestClient, caplog) -> None:
    rid = "r-abc"
    with caplog.at_level("INFO", logger="access"):
        response = client.get("/health", headers={"X-Request-ID": rid})
    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == rid

    found = False
    for payload in _access_log_records(caplog):
        if _extract_request_id_from_log(payload) == rid:
            found = True
            break
    assert found, "access log did not emit the same request_id as the header"


def test_access_log_matches_generated_uuid4_request_id(client: TestClient, caplog) -> None:
    with caplog.at_level("INFO", logger="access"):
        response = client.get("/health")
    assert response.status_code == 200
    rid = response.headers.get("X-Request-ID", "")
    assert UUID4_RE.match(rid), f"not a UUID4: {rid}"

    found = False
    for payload in _access_log_records(caplog):
        if _extract_request_id_from_log(payload) == rid:
            found = True
            break
    assert found, "access log request_id did not match response header UUID4"
