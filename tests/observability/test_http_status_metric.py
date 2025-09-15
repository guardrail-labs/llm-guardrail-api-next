from starlette.testclient import TestClient
from fastapi import APIRouter


def test_http_status_records_200_404_and_500():
    from app.main import create_app

    app = create_app()

    r = APIRouter()

    @r.get("/boom")
    async def boom():  # noqa: D401
        raise RuntimeError("boom")

    app.include_router(r)

    c = TestClient(app, raise_server_exceptions=False)
    # 200
    assert c.get("/health").status_code == 200
    # 404
    assert c.get("/definitely-not-here").status_code == 404
    # 500
    assert c.get("/boom").status_code == 500

    metrics = c.get("/metrics").text
    assert "guardrail_http_status_total" in metrics
    assert 'status="200"' in metrics
    assert 'status="404"' in metrics
    assert 'status="500"' in metrics
