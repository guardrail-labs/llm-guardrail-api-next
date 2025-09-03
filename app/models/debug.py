from __future__ import annotations

from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class RedactionSpan(BaseModel):
    start: int = Field(ge=0)
    end: int = Field(ge=0)
    label: str  # e.g., "[REDACTED:EMAIL]"
    family: Optional[str] = None  # e.g., "pii:email"


class SourceDebug(BaseModel):
    origin: str  # "ingress" | "egress"
    modality: str  # "text" | "file" | "image" | "audio" | "pdf"

    filename: Optional[str] = None
    mime_type: Optional[str] = None
    size_bytes: Optional[int] = None
    page: Optional[int] = None

    sha256: Optional[str] = None
    content_fingerprint: Optional[str] = None

    rule_hits: Dict[str, List[str]] = Field(default_factory=dict)
    redactions: List[RedactionSpan] = Field(default_factory=list)


class DebugPayload(BaseModel):
    sources: List[SourceDebug] = Field(default_factory=list)
