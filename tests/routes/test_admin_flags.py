import os

from fastapi.testclient import TestClient

from app.main import app
from app.services import runtime_flags

client = TestClient(app)
ADMIN_TOKEN = "test-token"


def _auth() -> dict[str, str]:
    return {"Authorization": f"Bearer {ADMIN_TOKEN}"}


def setup_function(_):
    os.environ["ADMIN_TOKEN"] = ADMIN_TOKEN
    runtime_flags.reset()


def teardown_function(_):
    runtime_flags.reset()


def test_unauthorized_endpoints():
    os.environ["ADMIN_TOKEN"] = ADMIN_TOKEN
    endpoints = [
        ("get", "/admin/flags"),
        ("post", "/admin/flags"),
        ("post", "/admin/policy/reload"),
        ("get", "/admin/snapshot"),
    ]
    for method, path in endpoints:
        if method == "post" and path == "/admin/flags":
            resp = getattr(client, method)(path, json={})
        else:
            resp = getattr(client, method)(path)
        assert resp.status_code == 401


def test_flags_update_and_snapshot():
    r = client.get("/admin/flags", headers=_auth())
    assert r.status_code == 200
    body = r.json()
    assert body["flags"]["verifier_sampling_pct"] == 0.0
    assert body["flags"]["pdf_detector_enabled"] is True

    r2 = client.post(
        "/admin/flags",
        headers=_auth(),
        json={"verifier_sampling_pct": 0.1, "pdf_detector_enabled": False},
    )
    assert r2.status_code == 200
    body2 = r2.json()
    assert 0.1 == body2["flags"]["verifier_sampling_pct"]
    assert body2["flags"]["pdf_detector_enabled"] is False

    r_bad = client.post("/admin/flags", headers=_auth(), json={"verifier_sampling_pct": 2})
    assert r_bad.status_code == 400

    r_reload = client.post("/admin/policy/reload", headers=_auth())
    assert r_reload.status_code == 200
    reload_body = r_reload.json()
    assert reload_body["ok"] is True
    assert isinstance(reload_body["version"], str)
    assert isinstance(reload_body["rules_count"], int)

    snap = client.get("/admin/snapshot", headers=_auth())
    assert snap.status_code == 200
    snap_body = snap.json()
    assert snap_body["features"]["pdf_detector"] is False
    assert snap_body["flags"]["verifier_sampling_pct"] == 0.1
