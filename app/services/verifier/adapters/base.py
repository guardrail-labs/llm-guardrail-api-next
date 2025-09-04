from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Literal, Mapping, Protocol

Verdict = Literal["safe", "unsafe", "unclear"]


class VerifierAdapter(Protocol):
    def assess(self, payload: Mapping[str, Any]) -> Verdict: ...


@dataclass(frozen=True)
class AdapterConfig:
    provider: str  # "none" | "openai" | "anthropic" | "azure"
    timeout_ms: int = 1500
    max_retries: int = 1
    circuit_open_sec: int = 60

    @classmethod
    def from_env(cls) -> "AdapterConfig":
        prov = os.getenv("VERIFIER_ADAPTER", "none").strip().lower()
        return cls(
            provider=prov,
            timeout_ms=int(os.getenv("VERIFIER_TIMEOUT_MS", "1500")),
            max_retries=int(os.getenv("VERIFIER_MAX_RETRIES", "1")),
            circuit_open_sec=int(os.getenv("VERIFIER_CIRCUIT_OPEN_SEC", "60")),
        )


class LocalRuleAdapter:
    """
    Deterministic, dependency-free adapter for CI and local dev.
    Uses trivial heuristics over payload fields; never raises.
    """

    def assess(self, payload: Mapping[str, Any]) -> Verdict:
        try:
            txt = str(payload.get("prompt_text", "")).lower()
            sources = payload.get("debug", {}).get("sources", [])
            # Heuristic hits from debug rule ids
            rule_hits = []
            for s in sources:
                rule_hits.extend(s.get("rule_hits", []))
            hit_text = any(k in txt for k in ("ignore safety", "server credentials", "api key"))
            hit_rules = any("override" in r or "exfil" in r for r in rule_hits)
            if hit_text or hit_rules:
                return "unsafe"
            return "safe" if txt else "unclear"
        except Exception:
            return "unclear"


def resolve_adapter_from_env() -> VerifierAdapter:
    _cfg = AdapterConfig.from_env()
    # For now, always return LocalRuleAdapter to avoid network calls in CI.
    # A follow-up PR can return provider-specific adapters based on _cfg.provider.
    return LocalRuleAdapter()
