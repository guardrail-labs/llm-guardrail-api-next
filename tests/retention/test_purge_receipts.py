from __future__ import annotations

import base64
import time

import pytest

from app.services.purge_receipts import (
    HmacSigner,
    PurgeReceipt,
    load_receipt,
    store_receipt,
)


def _receipt() -> PurgeReceipt:
    now = time.time()
    return PurgeReceipt.build(
        tenant="acme",
        resource="dlq_msg",
        count=3,
        ids=["a", "b", "c"],
        started_ts=now - 1,
        completed_ts=now,
        actor="tester",
        mode="manual",
        dry_run=False,
        meta={"host": "unit"},
    )


def test_hmac_sign_and_verify() -> None:
    signer = HmacSigner(b"secret-key", "kid-1")
    receipt = _receipt()
    signature = signer.sign(receipt)
    assert signer.verify(receipt, signature)


def test_hmac_detects_tampering() -> None:
    signer = HmacSigner(b"secret-key", "kid-1")
    receipt = _receipt()
    signature = signer.sign(receipt)
    tampered = PurgeReceipt(
        id=receipt.id,
        tenant=receipt.tenant,
        resource=receipt.resource,
        count=receipt.count + 1,
        ids=list(receipt.ids),
        started_ts=receipt.started_ts,
        completed_ts=receipt.completed_ts,
        actor=receipt.actor,
        mode=receipt.mode,
        dry_run=receipt.dry_run,
        truncated_ids=receipt.truncated_ids,
        meta=dict(receipt.meta),
    )
    assert not signer.verify(tampered, signature)


@pytest.mark.asyncio
async def test_store_receipt_includes_key_id() -> None:
    fakeredis = pytest.importorskip("fakeredis.aioredis")
    redis = fakeredis.FakeRedis(decode_responses=False)
    receipt = _receipt()
    signer = HmacSigner(base64.b64decode(base64.b64encode(b"secret")), "kid-2")
    signature = signer.sign(receipt)
    await store_receipt(redis, receipt, signature)
    stored = await load_receipt(redis, receipt.id)
    assert stored is not None
    _, stored_signature = stored
    assert stored_signature.get("kid") == "kid-2"
