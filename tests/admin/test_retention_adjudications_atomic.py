from __future__ import annotations

from datetime import datetime, timezone

from app.observability import adjudication_log as log
from app.services import retention


def _ts(ms: int) -> str:
    dt = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def test_adjudication_retention_keeps_newer_records() -> None:
    base = 1_700_000_000_000
    log.clear()

    log.append(
        log.AdjudicationRecord(
            ts=_ts(base - 10),
            request_id="old",
            tenant="tenant",
            bot="bot",
            provider="provider",
            decision="allow",
            rule_hits=[],
            score=None,
            latency_ms=0,
            policy_version=None,
            rules_path=None,
            sampled=False,
            prompt_sha256=None,
        )
    )
    log.append(
        log.AdjudicationRecord(
            ts=_ts(base + 10),
            request_id="new",
            tenant="tenant",
            bot="bot",
            provider="provider",
            decision="allow",
            rule_hits=[],
            score=None,
            latency_ms=0,
            policy_version=None,
            rules_path=None,
            sampled=False,
            prompt_sha256=None,
        )
    )

    deleted = retention.delete_adjudications_before(base, tenant="tenant", bot="bot", limit=10)
    assert deleted == 1

    remaining = [record.request_id for record in log._snapshot_records_desc()]
    assert remaining == ["new"]
