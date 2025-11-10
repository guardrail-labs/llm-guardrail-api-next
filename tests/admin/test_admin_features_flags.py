from importlib import reload

from fastapi.testclient import TestClient


def test_features_reflect_config(monkeypatch):
    monkeypatch.setenv("ADMIN_ENABLE_GOLDEN_ONE_CLICK", "true")

    import app.config as config

    reload(config)
    from app.main import create_app

    app = create_app()
    with TestClient(app) as client:
        resp = client.get("/admin/api/features")

    assert resp.status_code == 200
    body = resp.json()
    assert body.get("golden_one_click") is True
