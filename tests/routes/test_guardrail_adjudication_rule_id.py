from __future__ import annotations

from app.observability import adjudication_log
from app.routes.guardrail import _log_adjudication


def test_log_adjudication_populates_primary_rule_id() -> None:
    adjudication_log.clear()
    try:
        _log_adjudication(
            request_id="req-123",
            tenant="tenant-x",
            bot="bot-y",
            decision="block",
            rule_ids=["r42", "rX"],
            latency_ms=25,
            policy_version="v-test",
            rules_path="/rules/path.yaml",
            sampled=False,
            prompt_sha256="deadbeef",
            provider="core",
            score=0.5,
        )

        records = list(adjudication_log.iter_records())
        assert len(records) == 1
        record = records[0]
        assert record.rule_id == "r42"
        assert record.rule_hits == ["r42", "rX"]
    finally:
        adjudication_log.clear()
