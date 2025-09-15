import json

from app.egress.redaction import redact_response_body


def test_tool_calls_removed_and_urls_redacted():
    obj = {
        "text": "Visit https://example.com and run:\n```rm -rf /```",
        "tool_calls": [
            {
                "type": "function",
                "function": {"name": "shell", "arguments": "rm -rf /"},
            }
        ],
        "function_call": {"name": "danger", "arguments": "{}"},
    }
    body = json.dumps(obj).encode("utf-8")
    result = redact_response_body(body, "application/json")
    doc = json.loads(result.decode("utf-8"))

    assert "tool_calls" not in doc and "function_call" not in doc
    assert "[redacted url]" in doc["text"]
    assert "redacted code" in doc["text"]
