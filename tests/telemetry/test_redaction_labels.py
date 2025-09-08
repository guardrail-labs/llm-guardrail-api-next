from __future__ import annotations

import importlib

import prometheus_client


def test_redaction_label_shapes() -> None:
    import app.telemetry.metrics as metrics

    prometheus_client.REGISTRY._names_to_collectors.clear()
    importlib.reload(metrics)

    metrics.inc_redaction("mask-only")
    metrics.inc_redaction("ingress", "mask-two")
    metrics.inc_redaction(direction="egress", mask="mask-three")
    metrics.inc_redaction(mask="mask-four")
    metrics.inc_redaction(direction=None, mask=None)

    # Ensure labels can be retrieved without error
    metrics.guardrail_redactions_total.labels("unknown", "mask-only")
    metrics.guardrail_redactions_total.labels("ingress", "mask-two")
    metrics.guardrail_redactions_total.labels("egress", "mask-three")

