# isort: skip_file
from fastapi import APIRouter


router = APIRouter()


@router.get("/health")
def healthz() -> dict[str, str]:
    return {"status": "ok"}
