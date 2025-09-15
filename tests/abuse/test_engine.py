from __future__ import annotations

from app.services.abuse.engine import (
    AbuseConfig,
    AbuseEngine,
    Subject,
    decision_headers,
    generate_incident_id,
)


def _sub() -> Subject:
    return Subject(api_key_hash="ak", ip_hash="ip", org_id="org", session_id="sess")


def test_first_strike_blocks_input_only() -> None:
    eng = AbuseEngine(
        cfg=AbuseConfig(
            strike_window_sec=600,
            tiers=[(3, "execute_locked", 3600), (5, "full_quarantine", 21600)],
        )
    )
    s = _sub()
    d1 = eng.record_unsafe(s, now=1000.0)
    assert d1 == "block_input_only"
    assert eng.current_mode(s, now=1000.1) == "allow"


def test_escalates_to_execute_locked_then_full_quarantine() -> None:
    eng = AbuseEngine(
        cfg=AbuseConfig(
            strike_window_sec=600,
            tiers=[(3, "execute_locked", 3600), (5, "full_quarantine", 21600)],
        )
    )
    s = _sub()
    # 1 → block_input_only
    assert eng.record_unsafe(s, now=1000.0) == "block_input_only"
    # 2 → still below tier
    assert eng.record_unsafe(s, now=1001.0) in ("block_input_only", "execute_locked")
    # 3 → execute_locked
    assert eng.record_unsafe(s, now=1002.0) == "execute_locked"
    assert eng.current_mode(s, now=1002.1) == "execute_locked"
    # 4 → still execute_locked
    assert eng.record_unsafe(s, now=1003.0) in ("execute_locked", "full_quarantine")
    # 5 → full_quarantine
    assert eng.record_unsafe(s, now=1004.0) == "full_quarantine"
    assert eng.current_mode(s, now=1004.1) == "full_quarantine"


def test_cooldown_expires_to_allow() -> None:
    # Short cooldowns to make the test simple
    cfg = AbuseConfig(
        strike_window_sec=10,
        tiers=[(2, "execute_locked", 5), (3, "full_quarantine", 7)],
    )
    eng = AbuseEngine(cfg=cfg)
    s = _sub()

    assert eng.record_unsafe(s, now=1000.0) == "block_input_only"
    assert eng.record_unsafe(s, now=1001.0) in ("block_input_only", "execute_locked")
    # 3rd strike escalates to full_quarantine (7s cooldown)
    assert eng.record_unsafe(s, now=1002.0) == "full_quarantine"
    assert eng.current_mode(s, now=1005.0) == "full_quarantine"  # still within 7s
    assert eng.current_mode(s, now=1010.0) == "allow"  # cooldown passed


def test_headers_and_incident_id_format() -> None:
    inc = generate_incident_id(now=0.0)  # 1970-01-01 for deterministic prefix
    assert inc.startswith("gr-1970-01-01-")
    h1 = decision_headers("block_input_only", inc, retry_after_s=None)
    assert h1["X-Guardrail-Decision"] == "deny"
    assert h1["X-Guardrail-Incident-ID"] == inc
    assert h1["X-Guardrail-Mode"] == "normal"
    assert "Retry-After" not in h1

    h2 = decision_headers("execute_locked", inc, retry_after_s=None)
    assert h2["X-Guardrail-Decision"] == "deny"
    assert h2["X-Guardrail-Mode"] == "execute_locked"

    h3 = decision_headers("full_quarantine", inc, retry_after_s=42)
    assert h3["X-Guardrail-Decision"] == "deny"
    assert h3["X-Guardrail-Mode"] == "full_quarantine"
    assert h3["Retry-After"] == "42"
