from app.scanners.token_sequence_detector import find_terms_tokenized


def test_token_window_simple_split():
    text = "pa-ss-word should match"
    hits = find_terms_tokenized(text, ["password"])
    assert hits.get("password", 0) >= 1


def test_token_window_casefold():
    text = "API_KEY and api-key and ApiKey"
    hits = find_terms_tokenized(text, ["api_key"])
    assert hits.get("api_key", 0) >= 1


def test_no_terms_configured():
    # If caller passes empty terms, nothing is matched
    hits = find_terms_tokenized("anything", [])
    assert hits == {}
