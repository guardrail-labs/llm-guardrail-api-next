import importlib
import time

import app.services.verifier as v


class FakeProv:
    name = "quota-prov"

    def __init__(self, seq):
        self._seq = list(seq)

    async def assess(self, text, meta=None):
        token = self._seq.pop(0) if self._seq else "ok"
        if token == "429":
            from app.services.verifier.providers.base import ProviderRateLimited

            raise ProviderRateLimited(retry_after_s=0.2)
        return {"status": "safe", "reason": "ok", "tokens_used": 1}


def run(coro):
    import asyncio

    return asyncio.run(coro)


def test_quota_skip(monkeypatch):
    import app.services.verifier.providers as prov

    monkeypatch.setenv("VERIFIER_PROVIDER_QUOTA_SKIP_ENABLED", "1")
    monkeypatch.setenv("VERIFIER_PROVIDERS", "quota-prov")

    inst = FakeProv(["429", "ok"])

    def _build(name):
        return inst if name == "quota-prov" else None

    monkeypatch.setattr(prov, "build_provider", _build, raising=True)
    importlib.reload(v)

    out1 = run(v.verify_intent("hello", {"tenant_id": "t", "bot_id": "b"}))
    assert out1["status"] in ("ambiguous",)

    out2 = run(v.verify_intent("hello", {"tenant_id": "t", "bot_id": "b"}))
    assert out2["status"] in ("ambiguous",)

    time.sleep(1.1)
    out3 = run(v.verify_intent("hello", {"tenant_id": "t", "bot_id": "b"}))
    assert out3["status"] in ("safe",)
