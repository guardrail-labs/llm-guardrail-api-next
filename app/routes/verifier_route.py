from fastapi import APIRouter

from app.models.verifier import VerifierInput
from app.services.verifier_client import call_verifier

router = APIRouter(prefix="/verifier", tags=["verifier"])


@router.post("/test")
async def verifier_test(inp: VerifierInput):
    return call_verifier(inp).model_dump()
