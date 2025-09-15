from fastapi import APIRouter
from fastapi.testclient import TestClient


def test_http_status_uses_route_pattern_not_concrete_path() -> None:
    from app.main import create_app

    app = create_app()
    router = APIRouter()

    @router.get("/echo/{item_id}")
    async def echo(item_id: str) -> dict[str, object]:
        return {"ok": True, "id": item_id}

    app.include_router(router)

    client = TestClient(app)
    assert client.get("/echo/ABC123").status_code == 200

    metrics = client.get("/metrics").text
    assert "guardrail_http_status_total" in metrics
    assert 'endpoint="/echo/{item_id}"' in metrics
    assert 'status="200"' in metrics
