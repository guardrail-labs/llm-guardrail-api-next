from __future__ import annotations

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_json_still_works():
    r = client.post("/guardrail/evaluate", json={"text": "hello"})
    assert r.status_code == 200
    body = r.json()
    assert body["action"] == "allow"
    assert "transformed_text" in body


def test_multipart_text_plus_image():
    files = [
        ("image", ("cat.jpg", b"\xff\xd8\xff\xdb", "image/jpeg")),
    ]
    data = {"text": "look at this"}
    r = client.post("/guardrail/evaluate", data=data, files=files)
    assert r.status_code == 200
    body = r.json()
    assert "[IMAGE:cat.jpg]" in body["transformed_text"]
    kinds = {d.get("tag") for d in body.get("decisions", []) if isinstance(d, dict)}
    assert "image" in kinds


def test_multipart_text_audio_and_file():
    files = [
        ("audio", ("note.wav", b"RIFF....WAVE", "audio/wav")),
        ("file", ("doc.pdf", b"%PDF-1.4", "application/pdf")),
    ]
    data = {"text": "meeting notes"}
    r = client.post("/guardrail/evaluate", data=data, files=files)
    assert r.status_code == 200
    body = r.json()
    assert "[AUDIO:note.wav]" in body["transformed_text"]
    assert "[FILE:doc.pdf]" in body["transformed_text"]
    tags = {d.get("tag") for d in body.get("decisions", []) if isinstance(d, dict)}
    assert {"audio", "file"}.issubset(tags)
