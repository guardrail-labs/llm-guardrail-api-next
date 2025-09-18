from app.services.policy_lint import lint_policy


def test_lint_duplicate_id_and_compile_error():
    policy = {
        "rules": {
            "redact": [
                {"id": "a", "pattern": "("},
                {"id": "a", "pattern": "foo"},
                {"id": "b", "pattern": ".*abc"},
                {"id": "email", "pattern": "\\S+@\\S+"},
            ]
        }
    }
    lints = lint_policy(policy)
    codes = {x.code for x in lints}
    assert "regex_compile_error" in codes
    assert any(x.code == "duplicate_id" and x.rule_id == "a" for x in lints)
    assert any(x.code == "overbroad_dotstar" for x in lints)
    assert any(x.code == "missing_word_boundary" for x in lints)


def test_lint_nested_quantifiers_warns():
    policy = {"rules": {"redact": [{"id": "n", "pattern": "(\\w+)+$"}]}}
    lints = lint_policy(policy)
    assert any(x.code == "nested_quantifiers" for x in lints)
