from __future__ import annotations

import hashlib
from typing import Dict, Iterable, List, Optional

from app.models.debug import DebugPayload, RedactionSpan, SourceDebug


def _sha256_bytes(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()


def make_source(
    *,
    origin: str,
    modality: str,
    filename: Optional[str] = None,
    mime_type: Optional[str] = None,
    size_bytes: Optional[int] = None,
    page: Optional[int] = None,
    content_bytes: Optional[bytes] = None,
    content_fingerprint: Optional[str] = None,
    rule_hits: Optional[Dict[str, List[str]]] = None,
    redactions: Optional[Iterable[tuple[int, int, str, Optional[str]]]] = None,
) -> SourceDebug:
    return SourceDebug(
        origin=origin,
        modality=modality,
        filename=filename,
        mime_type=mime_type,
        size_bytes=size_bytes,
        page=page,
        sha256=_sha256_bytes(content_bytes) if content_bytes else None,
        content_fingerprint=content_fingerprint,
        rule_hits=rule_hits or {},
        redactions=[
            RedactionSpan(start=s, end=e, label=lab, family=fam)
            for (s, e, lab, fam) in (redactions or [])
        ],
    )


def merge_debug_payload(*payloads: Optional[DebugPayload]) -> DebugPayload:
    out = DebugPayload()
    for p in payloads:
        if not p:
            continue
        out.sources.extend(p.sources)
    return out
