"""
UPIPE: Unified pipeline stub — swap with real analyzers (regex/ML/LLM calls).
For now: returns empty decisions list.
"""

from dataclasses import dataclass

@dataclass
class Decision:
    rule_id: str
    rationale: str

def analyze(text: str) -> list[Decision]:
    # TODO: implement real detections (prompt injection, secrets, etc.)
    return []
