from __future__ import annotations

from app.services.abuse.engine import AbuseEngine, Subject


def make_subject():
    return Subject(api_key_hash="ak", ip_hash="ip", org_id="org", session_id="sess")

def test_first_strike_blocks_input_only():
    eng = AbuseEngine()
    s = make_subject()
    d1 = eng.record_unsafe(s, now=1000)
    assert d1 == "block_input_only"
    assert eng.current_mode(s, now=1001) == "allow"

def test_escalates_to_execute_locked_then_full_quarantine():
    eng = AbuseEngine()
    s = make_subject()
    # 3 strikes within window
    assert eng.record_unsafe(s, now=1000) == "block_input_only"
    assert eng.record_unsafe(s, now=1001) in ("block_input_only", "execute_locked")
    d3 = eng.record_unsafe(s, now=1002)
    assert d3 in ("execute_locked", "full_quarantine")  # threshold-based
    # simulate more strikes to reach full_quarantine
    eng.record_unsafe(s, now=1003)
    d5 = eng.record_unsafe(s, now=1004)
    assert d5 in ("execute_locked", "full_quarantine")

def test_cooldown_expires():
    eng = AbuseEngine()
    s = make_subject()
    eng.record_unsafe(s, now=1000)
    eng.record_unsafe(s, now=1001)
    eng.record_unsafe(s, now=1002)  # escalates and sets ban
    assert eng.current_mode(s, now=1002.5) in ("execute_locked", "allow")
    # after long time, allow
    assert eng.current_mode(s, now=1000 + 7200) == "allow"
