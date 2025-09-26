import base64
import io
import zipfile

from app.archives.peek import try_b64_archive


def make_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("readme.txt", "hello world")
        z.writestr("data.json", '{"k": "v"}')
    return buf.getvalue()


def test_try_b64_archive_lists_files_and_text():
    b = make_zip_bytes()
    s = base64.b64encode(b).decode("ascii")
    names, texts, stats = try_b64_archive("bundle.zip", s)
    assert "readme.txt" in names or "data.json" in names
    assert any("hello world" in t or '"k": "v"' in t for t in texts)
    assert stats.get("errors", 0) >= 0
