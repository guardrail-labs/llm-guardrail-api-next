from app.routes.openai_compat import ChatMessage, _apply_sanitized_text_to_messages


def test_preserves_multiline_and_only_changes_when_needed():
    original = [
        ChatMessage(role="system", content="Rules:\n- Be nice\n- Stay safe"),
        ChatMessage(role="user", content="Line A\nLine B\nLine C"),
        ChatMessage(role="assistant", content="Reply line 1\nReply line 2"),
    ]

    # Sanitized transcript that preserves multiline, tweaks the user content
    sanitized = (
        "system: Rules:\n"
        "- Be nice\n"
        "- Stay safe\n"
        "user: Line A\n"
        "Line B (sanitized)\n"
        "Line C\n"
        "assistant: Reply line 1\n"
        "Reply line 2\n"
    )

    updated = _apply_sanitized_text_to_messages(original, sanitized)

    # system unchanged
    assert updated[0].content == "Rules:\n- Be nice\n- Stay safe"
    # user changed (middle line updated)
    assert updated[1].content == "Line A\nLine B (sanitized)\nLine C"
    # assistant unchanged
    assert updated[2].content == "Reply line 1\nReply line 2"


def test_noop_when_sanitized_has_no_blocks():
    original = [ChatMessage(role="user", content="Hello\nWorld")]
    sanitized = "noise without any role markers"
    updated = _apply_sanitized_text_to_messages(original, sanitized)
    assert updated is original  # identity: function returns same list if no changes


def test_multiple_messages_same_role_fifo():
    original = [
        ChatMessage(role="user", content="one"),
        ChatMessage(role="assistant", content="a1"),
        ChatMessage(role="user", content="two"),
    ]
    sanitized = "user: ONE\nassistant: a1\nuser: TWO\n"
    updated = _apply_sanitized_text_to_messages(original, sanitized)
    assert [m.content for m in updated] == ["ONE", "a1", "TWO"]
