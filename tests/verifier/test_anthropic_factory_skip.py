import importlib

import app.services.verifier.providers as prov
import app.settings as settings


def test_factory_skips_without_key(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "")
    importlib.reload(settings)
    importlib.reload(prov)
    p = prov.build_provider("anthropic")
    assert p is None
