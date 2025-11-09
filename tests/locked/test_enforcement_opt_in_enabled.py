from app.services import enforcement as enf


def test_enabled_execute_locked_paths(monkeypatch):
    monkeypatch.setenv("LOCK_ENABLE", "true")
    monkeypatch.setenv("LOCK_DENY_AS_EXECUTE", "true")
    # Policy lock honored
    assert enf.choose_mode(policy_result={"action": "lock"}, family="deny") == "execute_locked"
    # Deny converted to execute_locked when configured
    assert enf.choose_mode(policy_result=None, family="deny") == "execute_locked"
    # Allow remains allow
    assert enf.choose_mode(policy_result=None, family="allow") == "allow"
