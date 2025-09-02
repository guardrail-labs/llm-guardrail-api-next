from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from app.compliance.pii import hash_email, hash_phone, redact_and_hash
from app.config import get_settings

router = APIRouter(prefix="/admin/compliance", tags=["admin"])


class HashIn(BaseModel):
    email: str | None = None
    phone: str | None = None
    text: str | None = None


@router.get("/status")
def status() -> dict:
    s = get_settings()
    return {
        "ok": True,
        "enabled": bool(s.COMPLIANCE_ENABLED),
        "retention_days": int(s.DATA_RETENTION_DAYS),
        "hash_algo": s.PII_HASH_ALGO,
        "email_hash": bool(s.PII_EMAIL_HASH_ENABLED),
        "phone_hash": bool(s.PII_PHONE_HASH_ENABLED),
    }


@router.post("/hash")
def do_hash(inp: HashIn) -> dict:
    out: dict = {"ok": True}
    if inp.email:
        out["email_hash"] = hash_email(inp.email)
    if inp.phone:
        out["phone_hash"] = hash_phone(inp.phone)
    if inp.text:
        sanitized, counters = redact_and_hash(inp.text)
        out["sanitized"] = sanitized
        out["counters"] = counters
    return out
