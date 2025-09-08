from __future__ import annotations

import uuid

from app.telemetry import metrics as m


def test_export_verifier_lines_emits_series() -> None:
    """Export should include a series for the incremented verifier/outcome."""
    # Use a unique label to avoid interference across runs.
    verifier = f"unittest-{uuid.uuid4().hex[:8]}"

    m.inc_verifier_outcome(verifier, "allow")

    lines = m.export_verifier_lines()
    # Must include at least one series for our unique verifier label.
    expected_prefix = (
        f'guardrail_verifier_outcome_total{{verifier="{verifier}",outcome="allow"}}'
    )
    assert any(line.startswith(expected_prefix) for line in lines), lines
