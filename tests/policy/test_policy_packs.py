from __future__ import annotations

import hashlib

from app.services.policy_packs import load_pack, merge_packs


def test_load_pack_base():
    ref, data, raw = load_pack("base")
    assert ref.name == "base"
    assert ref.path.endswith(("base.yaml", "base.yml"))
    assert isinstance(data, dict)
    assert "meta" in data and "rules" in data
    assert isinstance(raw, (bytes, bytearray))

    version_piece = hashlib.sha256(ref.name.encode() + b"\x00" + raw).hexdigest()
    assert len(version_piece) == 64


def test_merge_order_and_override():
    merged, version, refs = merge_packs(["base", "hipaa"])
    assert refs[0].name == "base"
    assert refs[1].name == "hipaa"
    assert merged["settings"]["egress"]["redact_enabled"] is True
    assert merged["settings"]["ingress"]["sampling_pct"] == 1.0

    redact_ids = [rule["id"] for rule in merged["rules"]["redact"]]
    assert "redact.phi.email" in redact_ids

    _, version_reordered, _ = merge_packs(["hipaa", "base"])
    assert version_reordered != version


def test_merge_three_packs():
    merged, _, refs = merge_packs(["base", "hipaa", "gdpr"])
    assert len(refs) == 3

    redact_ids = [rule["id"] for rule in merged["rules"]["redact"]]
    assert "redact.phi.email" in redact_ids
    assert "redact.pii.phone" in redact_ids

    assert merged["settings"]["data_retention_days"] == 30
