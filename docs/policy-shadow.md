# Shadow policy evaluation

Shadow mode lets you exercise a candidate policy alongside the live, enforced
configuration. The shadow result never influences the response returned to the
caller, but it is evaluated synchronously (with a tight timeout budget) so that
we can surface disagreements through metrics, admin feeds, and dashboards.

## Why shadow policies matter

* Validate changes before flipping them live. You can confirm that a stricter
  policy behaves as expected and quantify the impact of looser rules.
* Detect regressions safely. Disagreement metrics highlight cases where the
  shadow action diverges from the enforced decision, grouped by route and the
  action pair (e.g. `allow→deny`).
* Preserve safety guarantees. Live enforcement still governs headers, status
  codes, and response bodies. Shadow evaluation only observes.

## Configuration

Shadow evaluation is controlled through the runtime configuration store and can
optionally be overridden via environment variables.

| Key | Description | Default | Env override |
| --- | ----------- | ------- | ------------- |
| `shadow_enable` | Enable shadow evaluation | `false` | `SHADOW_ENABLE` |
| `shadow_policy_path` | Path to the candidate policy JSON | `""` | `SHADOW_POLICY_PATH` |
| `shadow_timeout_ms` | Budget for the shadow evaluator | `100` | `SHADOW_TIMEOUT_MS` |
| `shadow_sample_rate` | Fraction of requests sampled (0..1) | `1.0` | `SHADOW_SAMPLE_RATE` |

All values are persisted via `config_store` and surfaced in the Admin UI →
Config page. Updates via the UI are written to `config/admin_config.yaml` and
are merged with environment overrides on start-up.

## Performance notes

* **Timeout budget:** Shadow evaluation is synchronous. Keep
  `shadow_timeout_ms` low to minimize tail latency impact. The result includes
  `_shadow_latency_ms` for observability.
* **Sampling:** Use `shadow_sample_rate` to reduce load. Values outside `[0, 1]`
  are clamped. When the sample rate is less than 1, a random draw gates
  execution.
* **Failure handling:** Any exception (e.g. file read errors or evaluator
  issues) causes the shadow run to be skipped. Live enforcement is unaffected.

## Observability

Metrics are exposed under
`guardrail_policy_disagreement_total{route,live_action,shadow_action}`. Each
increment represents a mismatch between the enforced action and the shadow
result.

Grafana panels (appended to `observability/grafana/guardrail.json`):

* **Policy disagreements by route (5m)** – table of disagreement rate per
  route.
* **Disagreements by live vs shadow action (5m)** – time-series grouped by the
  action transition (e.g. `allow→deny`).

Decision events now include `shadow_action` and `shadow_rule_ids`, so the Admin
feed, CSV export, and SSE stream all carry the additional fields. When the
shadow run is disabled or skipped, `shadow_action` is `null` and the rule list
is empty.

## Promoting a shadow policy

1. Enable shadow mode and point `shadow_policy_path` at the candidate policy
   file (e.g. a JSON export).
2. Monitor `guardrail_policy_disagreement_total` via `/metrics` or Grafana.
   Investigate high-traffic routes and notable action changes.
3. Review admin decisions to spot individual divergences (the UI now surfaces
   shadow metadata).
4. When satisfied, disable shadow mode and promote the candidate policy through
   your normal deployment path (e.g. updating the live policy bundle).

Shadow evaluation is safe by design: it never modifies live responses and all
telemetry is additive. Use it as a rehearsal space for policy updates.
