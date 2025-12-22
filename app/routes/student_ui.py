from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse

router = APIRouter(tags=["student-ui"])

_STATIC_DIR = Path(__file__).resolve().parent.parent / "static" / "student"
_INDEX_PATH = _STATIC_DIR / "index.html"


def _load_index_html() -> str:
    try:
        return _INDEX_PATH.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Student UI not found") from exc


@router.get("/student", response_class=HTMLResponse, include_in_schema=False)
def student_ui() -> HTMLResponse:
    return HTMLResponse(_load_index_html())


@router.get("/student/", response_class=HTMLResponse, include_in_schema=False)
def student_ui_slash() -> HTMLResponse:
    return HTMLResponse(_load_index_html())
