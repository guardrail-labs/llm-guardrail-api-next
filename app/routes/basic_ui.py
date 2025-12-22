from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse

router = APIRouter(tags=["basic-ui"])

_STATIC_DIR = Path(__file__).resolve().parent.parent / "static" / "basic"
_INDEX_PATH = _STATIC_DIR / "index.html"


def _load_index_html() -> str:
    try:
        return _INDEX_PATH.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Basic UI not found") from exc


@router.get("/basic", response_class=HTMLResponse, include_in_schema=False)
def basic_ui() -> HTMLResponse:
    return HTMLResponse(_load_index_html())


@router.get("/basic/", response_class=HTMLResponse, include_in_schema=False)
def basic_ui_slash() -> HTMLResponse:
    return HTMLResponse(_load_index_html())
