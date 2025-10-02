# Idempotency Chaos & Soak Tests

- `test_idemp_backoff_and_replay.py`: contention → single leader, followers replay.
- `test_idemp_ttl_refresh.py`: `touch_on_replay` extends TTL.
- `soak_idemp.py` (`@pytest.mark.soak`): mixed traffic with some conflicts.

## Run

```bash
pytest -q tests/chaos
# include soak:
pytest -q -m soak tests/chaos
```
