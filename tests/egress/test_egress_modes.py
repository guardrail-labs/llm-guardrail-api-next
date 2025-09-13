from fastapi.responses import StreamingResponse
from fastapi.testclient import TestClient

from app.main import app


@app.get("/demo/egress-json")
def _egress_json():
    return {"email": "user@example.com"}


@app.get("/demo/stream")
async def _egress_stream():
    async def gen():
        yield "data: hello\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream")


client = TestClient(app)


def test_egress_json_redact_and_annotate():
    r = client.get("/demo/egress-json")
    assert r.status_code == 200
    j = r.json()
    assert j["email"] == "[REDACTED-EMAIL]"
    assert r.headers.get("X-Guardrail-Decision") == "allow"


def test_egress_streaming_untouched():
    r = client.get("/demo/stream", headers={"accept": "text/event-stream"})
    assert r.status_code == 200
    assert "text/event-stream" in r.headers.get("content-type", "").lower()
    assert "content-length" not in {k.lower() for k in r.headers}

