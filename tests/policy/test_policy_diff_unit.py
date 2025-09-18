from app.services.policy_diff import diff_policies


def test_diff_detects_added_removed_changed():
    cur = {"rules": {"redact": [{"id": "a", "pattern": "x"}, {"id": "b", "pattern": "y"}]}}
    new = {"rules": {"redact": [{"id": "a", "pattern": "x2"}, {"id": "c", "pattern": "z"}]}}
    diff = diff_policies(cur, new)
    assert diff["summary"] == {
        "added": 1,
        "removed": 1,
        "changed": 1,
        "total_current": 2,
        "total_new": 2,
    }
    assert diff["added"][0]["id"] == "c"
    assert diff["removed"][0]["id"] == "b"
    assert diff["changed"][0]["id"] == "a"
    assert "pattern" in diff["changed"][0]["changes"]
