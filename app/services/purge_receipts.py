from __future__ import annotations

import base64
import json
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Protocol, Tuple, cast

from redis.asyncio import Redis

MAX_RECEIPT_IDS = 100


def _canonical_json(data: Any) -> bytes:
    return json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")


@dataclass(slots=True)
class PurgeReceipt:
    id: str
    tenant: str
    resource: str
    count: int
    ids: List[str] = field(default_factory=list)
    started_ts: float = field(default_factory=lambda: time.time())
    completed_ts: float = field(default_factory=lambda: time.time())
    actor: str = "unknown"
    mode: str = "manual"
    dry_run: bool = False
    truncated_ids: bool = False
    meta: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def build(
        cls,
        tenant: str,
        resource: str,
        *,
        count: int,
        ids: Iterable[str],
        started_ts: float,
        completed_ts: float,
        actor: str,
        mode: str,
        dry_run: bool,
        meta: Optional[Dict[str, str]] = None,
    ) -> "PurgeReceipt":
        all_ids = [str(item) for item in ids]
        truncated = len(all_ids) > MAX_RECEIPT_IDS
        kept = all_ids[:MAX_RECEIPT_IDS]
        return cls(
            id=uuid.uuid4().hex,
            tenant=tenant,
            resource=resource,
            count=int(count),
            ids=kept,
            started_ts=float(started_ts),
            completed_ts=float(completed_ts),
            actor=str(actor or "unknown"),
            mode=str(mode or "manual"),
            dry_run=bool(dry_run),
            truncated_ids=truncated,
            meta=dict(meta or {}),
        )

    def to_payload(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "tenant": self.tenant,
            "resource": self.resource,
            "count": int(self.count),
            "ids": list(self.ids),
            "started_ts": float(self.started_ts),
            "completed_ts": float(self.completed_ts),
            "actor": self.actor,
            "mode": self.mode,
            "dry_run": bool(self.dry_run),
            "truncated_ids": bool(self.truncated_ids),
            "meta": dict(self.meta),
        }


class Signer(Protocol):
    def sign(self, receipt: PurgeReceipt) -> Dict[str, str]: ...

    def verify(self, receipt: PurgeReceipt, signature: Dict[str, str]) -> bool: ...


class HmacSigner:
    def __init__(self, secret: bytes, key_id: str) -> None:
        import hashlib
        import hmac

        self._secret = bytes(secret)
        if not self._secret:
            raise ValueError("HMAC secret must not be empty")
        self._key_id = key_id
        self._hashlib = hashlib
        self._hmac = hmac

    def sign(self, receipt: PurgeReceipt) -> Dict[str, str]:
        message = _canonical_json(receipt.to_payload())
        digest = self._hmac.new(self._secret, message, self._hashlib.sha256).digest()
        return {
            "alg": "HS256",
            "kid": self._key_id,
            "sig": base64.b64encode(digest).decode("ascii"),
        }

    def verify(self, receipt: PurgeReceipt, signature: Dict[str, str]) -> bool:
        if signature.get("alg") != "HS256":
            return False
        expected = self.sign(receipt)["sig"]
        provided = signature.get("sig", "")
        return self._hmac.compare_digest(str(provided), expected)


class Ed25519Signer:
    def __init__(self, priv_b64: str, key_id: str) -> None:
        try:
            from nacl import signing
        except Exception as exc:  # pragma: no cover - optional dependency guard
            raise RuntimeError("PyNaCl required for Ed25519 signing") from exc
        private_bytes = base64.b64decode(priv_b64)
        self._signing_key = signing.SigningKey(private_bytes)
        self._verify_key = self._signing_key.verify_key
        self._key_id = key_id

    def sign(self, receipt: PurgeReceipt) -> Dict[str, str]:
        message = _canonical_json(receipt.to_payload())
        signature = self._signing_key.sign(message).signature
        return {
            "alg": "Ed25519",
            "kid": self._key_id,
            "sig": base64.b64encode(signature).decode("ascii"),
        }

    def verify(self, receipt: PurgeReceipt, signature: Dict[str, str]) -> bool:
        if signature.get("alg") != "Ed25519":
            return False
        try:
            encoded = base64.b64decode(signature.get("sig", ""))
            message = _canonical_json(receipt.to_payload())
            self._verify_key.verify(message, encoded)
            return True
        except Exception:
            return False


async def store_receipt(redis: Redis, receipt: PurgeReceipt, signature: Dict[str, str]) -> None:
    key = f"retention:receipt:{receipt.id}"
    payload = {
        "receipt": receipt.to_payload(),
        "signature": dict(signature),
    }
    await redis.set(key, _canonical_json(payload))
    zset_key = f"retention:receipt:tenant:{receipt.tenant}"
    await redis.zadd(zset_key, {receipt.id: receipt.completed_ts})


async def load_receipt(
    redis: Redis, receipt_id: str
) -> Optional[Tuple[PurgeReceipt, Dict[str, str]]]:
    key = f"retention:receipt:{receipt_id}"
    raw = await redis.get(key)
    if raw is None:
        return None
    raw_bytes = cast(bytes, raw)
    payload = json.loads(raw_bytes.decode("utf-8"))
    body = payload.get("receipt", {})
    receipt = PurgeReceipt(
        id=str(body.get("id", receipt_id)),
        tenant=str(body.get("tenant", "")),
        resource=str(body.get("resource", "")),
        count=int(body.get("count", 0)),
        ids=[str(item) for item in body.get("ids", [])],
        started_ts=float(body.get("started_ts", 0.0)),
        completed_ts=float(body.get("completed_ts", 0.0)),
        actor=str(body.get("actor", "unknown")),
        mode=str(body.get("mode", "manual")),
        dry_run=bool(body.get("dry_run", False)),
        truncated_ids=bool(body.get("truncated_ids", False)),
        meta={str(k): str(v) for k, v in dict(body.get("meta", {})).items()},
    )
    signature = {
        str(k): str(v) for k, v in dict(payload.get("signature", {})).items() if v is not None
    }
    return receipt, signature


async def latest_receipts(redis: Redis, tenant: str, limit: int) -> List[PurgeReceipt]:
    if limit <= 0:
        return []
    key = f"retention:receipt:tenant:{tenant}"
    ids = await redis.zrevrange(key, 0, max(limit - 1, 0))
    if not ids:
        return []
    decoded = [item.decode("utf-8") if isinstance(item, bytes) else str(item) for item in ids]
    pipe = redis.pipeline()
    for receipt_id in decoded:
        pipe.get(f"retention:receipt:{receipt_id}")
    raw_items = await pipe.execute()
    receipts: List[PurgeReceipt] = []
    for receipt_id, raw in zip(decoded, raw_items):
        if raw is None:
            continue
        stored = await load_receipt(redis, receipt_id)
        if stored is None:
            continue
        receipts.append(stored[0])
    return receipts


def signer_from_env() -> Signer:
    secret_b64 = os.getenv("PURGE_SIGNING_SECRET", "")
    key_id = os.getenv("PURGE_KEY_ID", "default-hmac")
    ed_priv = os.getenv("PURGE_ED25519_PRIV")
    if ed_priv:
        return Ed25519Signer(ed_priv, key_id)
    if not secret_b64:
        secret_b64 = base64.b64encode(b"insecure-test").decode("ascii")
    secret = base64.b64decode(secret_b64)
    return HmacSigner(secret, key_id)


__all__ = [
    "Ed25519Signer",
    "HmacSigner",
    "MAX_RECEIPT_IDS",
    "PurgeReceipt",
    "Signer",
    "latest_receipts",
    "load_receipt",
    "signer_from_env",
    "store_receipt",
]
