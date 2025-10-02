# Idempotency Chaos & Soak Tests

- `test_idemp_backoff_and_replay.py`: contention → single leader, followers replay.
- `test_idemp_ttl_refresh.py`: `touch_on_replay` extends TTL.
- `soak_idemp.py` (`@pytest.mark.soak`): mixed traffic with some conflicts.

## Run

```bash
pytest -q tests/chaos
# or include soak:
pytest -q -m soak tests/chaos
```

### CI notes
- No CI changes required. Soak test is opt-in via `-m soak`.  
- Regular chaos tests live under `tests/chaos/` and run with the standard suite.

### Acceptance criteria
- `pytest -q tests/chaos` passes locally and in CI.
- No lines > 100 chars; no unused imports.
- Tests are deterministic enough to avoid flakes (tiny sleeps only in soak).

---

## notes / summary (for you)

- We avoided introspecting metric internals; assertions rely on headers and execution counts.
- `RecordingStore` emulates TTL and lock meta so middleware logic exercises follower backoff.
- The soak test is opt-in to keep CI quick; it gives you a knob for heavier runs if needed.
