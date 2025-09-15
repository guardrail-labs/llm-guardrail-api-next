from app.services import enforcement as enf


def test_defaults_off_no_execute_locked(monkeypatch):
    monkeypatch.delenv("LOCK_ENABLE", raising=False)
    monkeypatch.delenv("LOCK_DENY_AS_EXECUTE", raising=False)

    # Deny stays deny when feature off
    assert enf.choose_mode(policy_result=None, family="deny") == "deny"
    # Explicit policy lock is treated as deny when feature off (harden-by-default)
    assert (
        enf.choose_mode(policy_result={"action": "lock"}, family="deny") == "deny"
    )
    # Allow stays allow
    assert enf.choose_mode(policy_result=None, family="allow") == "allow"
