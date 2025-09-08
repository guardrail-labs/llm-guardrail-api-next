import os


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except Exception:
        return default


# Verifier hardening
VERIFIER_TIMEOUT_MS = _int("VERIFIER_TIMEOUT_MS", 2500)
VERIFIER_MAX_TOKENS_PER_REQUEST = _int("VERIFIER_MAX_TOKENS_PER_REQUEST", 800)
VERIFIER_DAILY_TOKEN_BUDGET = _int("VERIFIER_DAILY_TOKEN_BUDGET", 100_000)
VERIFIER_CIRCUIT_FAILS = _int("VERIFIER_CIRCUIT_FAILS", 5)
VERIFIER_CIRCUIT_WINDOW_S = _int("VERIFIER_CIRCUIT_WINDOW_S", 300)
VERIFIER_CIRCUIT_COOLDOWN_S = _int("VERIFIER_CIRCUIT_COOLDOWN_S", 600)
