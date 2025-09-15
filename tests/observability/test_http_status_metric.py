from fastapi import APIRouter
from fastapi.testclient import TestClient


def test_http_status_records_200_404_and_500() -> None:
    from app.main import create_app

    app = create_app()
    router = APIRouter()

    @router.get("/boom")
    async def boom() -> dict[str, str]:
        raise RuntimeError("boom")

    app.include_router(router)

    client = TestClient(app, raise_server_exceptions=False)
    assert client.get("/health").status_code == 200  # 200
    assert client.get("/definitely-not-here").status_code == 404  # 404
    assert client.get("/boom").status_code == 500  # 500

    body = client.get("/metrics").text
    assert "guardrail_http_status_total" in body
    for code in ("200", "404", "500"):
        assert f'status="{code}"' in body
