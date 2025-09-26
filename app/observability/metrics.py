from __future__ import annotations

import os
from dataclasses import dataclass
import logging
from typing import Any, Callable, Optional, Set, Tuple

from prometheus_client import REGISTRY, CollectorRegistry, Counter, Gauge, Histogram

_CARD_MAX_RAW = (
    os.getenv("METRICS_LABEL_CARD_MAX")
    or os.getenv("METRICS_LABEL_CARDINALITY_MAX")
    or "1000"
)
_METRICS_LABEL_CARD_MAX = int(_CARD_MAX_RAW or "1000")
_PAIR_MAX_RAW = (
    os.getenv("METRICS_LABEL_PAIR_CARD_MAX")
    or os.getenv("METRICS_LABEL_PAIR_CARDINALITY_MAX")
    or str(_METRICS_LABEL_CARD_MAX)
)
_METRICS_LABEL_PAIR_CARD_MAX = int(_PAIR_MAX_RAW or str(_METRICS_LABEL_CARD_MAX))
_METRICS_LABEL_OVERFLOW = os.getenv("METRICS_LABEL_OVERFLOW", "__overflow__")

_seen_tenants: Set[str] = set()
_seen_bots: Set[str] = set()
_seen_pairs: Set[Tuple[str, str]] = set()

_log = logging.getLogger(__name__)


# -----------------------------------------------------------------------------
# Best-effort helper for observability: do not raise from metrics code paths.
# We intentionally keep failures non-fatal, but we *do* record debug context
# to help diagnose misconfigurations in production.
# -----------------------------------------------------------------------------
def _best_effort(msg: str, fn: Callable[[], Any]) -> None:
    try:
        fn()
    except Exception as e:  # pragma: no cover
        # nosec B110 - metrics should never crash request paths; debug for ops.
        _log.debug("%s: %s", msg, e)


def _safe_label(val: str, cache: Set[str]) -> str:
    if not val:
        return "unknown"
    if val in cache:
        return val
    if len(cache) < _METRICS_LABEL_CARD_MAX:
        cache.add(val)
        return val
    return _METRICS_LABEL_OVERFLOW


def _limit_tenant_bot_labels(tenant: str, bot: str) -> Tuple[str, str]:
    tenant_l = _safe_label(str(tenant), _seen_tenants)
    bot_l = _safe_label(str(bot), _seen_bots)
    if _METRICS_LABEL_OVERFLOW in {tenant_l, bot_l}:
        return _METRICS_LABEL_OVERFLOW, _METRICS_LABEL_OVERFLOW
    pair = (tenant_l, bot_l)
    if pair in _seen_pairs:
        return pair
    if len(_seen_pairs) < _METRICS_LABEL_PAIR_CARD_MAX:
        _seen_pairs.add(pair)
        return pair
    return _METRICS_LABEL_OVERFLOW, _METRICS_LABEL_OVERFLOW



def _get_or_create_counter(
    name: str,
    doc: str,
    labelnames: Tuple[str, ...] = (),
    registry: Optional[CollectorRegistry] = None,
) -> Counter:
    reg = registry or REGISTRY
    # Try to reuse an existing collector if already registered.
    try:
        names_map = getattr(reg, "_names_to_collectors", None)
        if isinstance(names_map, dict):
            existing = names_map.get(name)
            if isinstance(existing, Counter):
                return existing
    except Exception as e:  # pragma: no cover
        _log.debug("reuse counter %s failed: %s", name, e)

    try:
        return Counter(name, doc, labelnames=labelnames, registry=reg)
    except ValueError:
        # Another module created it first; fetch and reuse.
        try:
            names_map = getattr(reg, "_names_to_collectors", None)
            if isinstance(names_map, dict):
                found = names_map.get(name)
                if isinstance(found, Counter):
                    return found
        except Exception as e:  # pragma: no cover
            _log.debug("fallback counter lookup %s failed: %s", name, e)
        # Final fallback: create an unregistered counter (won't be exposed).
        return Counter(name, doc, labelnames=labelnames)


# --- Metadata / headers metrics ------------------------------------------------

_metadata_headers_changed_total = _get_or_create_counter(
    "guardrail_metadata_headers_changed_total",
    "Headers sanitized/normalized at ingress",
    ("tenant", "bot"),
)
_metadata_filenames_sanitized_total = _get_or_create_counter(
    "guardrail_metadata_filenames_sanitized_total",
    "Filenames sanitized in headers or JSON",
    ("tenant", "bot"),
)
_metadata_truncated_total = _get_or_create_counter(
    "guardrail_metadata_truncated_total",
    "Values truncated due to length limits",
    ("tenant", "bot"),
)


def metadata_ingress_report(
    *,
    tenant: str = "",
    bot: str = "",
    headers_changed: int = 0,
    filenames_sanitized: int = 0,
    truncated: int = 0,
) -> None:
    tenant_l, bot_l = _limit_tenant_bot_labels(tenant, bot)

    def _do() -> None:
        if headers_changed:
            _metadata_headers_changed_total.labels(
                tenant=tenant_l, bot=bot_l
            ).inc(headers_changed)
        if filenames_sanitized:
            _metadata_filenames_sanitized_total.labels(
                tenant=tenant_l, bot=bot_l
            ).inc(filenames_sanitized)
        if truncated:
            _metadata_truncated_total.labels(tenant=tenant_l, bot=bot_l).inc(
                truncated
            )

    _best_effort("inc metadata ingress metrics", _do)


# --- Tokenizer-aware scan metrics -------------------------------------------


_token_scan_hits_total = _get_or_create_counter(
    "guardrail_token_scan_hits_total",
    "Tokenizer-aware matches for configured terms",
    ("tenant", "bot", "term"),
)


def token_scan_report(
    *, tenant: str = "", bot: str = "", hits: dict[str, int] | None = None
) -> None:
    if not hits:
        return
    tenant_l, bot_l = _limit_tenant_bot_labels(tenant, bot)

    def _do() -> None:
        for term, count in hits.items():
            if count:
                _token_scan_hits_total.labels(
                    tenant=tenant_l, bot=bot_l, term=term
                ).inc(count)

    _best_effort("inc token scan metrics", _do)


# --- Emoji ZWJ / TAG metrics ---------------------------------------------------

_emoji_fields_total = _get_or_create_counter(
    "guardrail_emoji_fields_total",
    "JSON string fields inspected for emoji ZWJ/TAG patterns",
    ("tenant", "bot"),
)
_emoji_tag_sequences_total = _get_or_create_counter(
    "guardrail_emoji_tag_sequences_total",
    "Emoji TAG sequences observed (with optional CANCEL TAG)",
    ("tenant", "bot"),
)
_emoji_zwj_total = _get_or_create_counter(
    "guardrail_emoji_zwj_total",
    "Zero-width joiners observed in JSON strings",
    ("tenant", "bot"),
)
_emoji_controls_total = _get_or_create_counter(
    "guardrail_emoji_controls_total",
    "Emoji-related control code points observed (ZWJ/ZWNJ/ZWSP/VS16/KEYCAP/TAG)",
    ("tenant", "bot"),
)
_emoji_hidden_text_bytes_total = _get_or_create_counter(
    "guardrail_emoji_hidden_text_bytes_total",
    "Bytes of ASCII revealed from TAG sequences",
    ("tenant", "bot"),
)


def emoji_zwj_ingress_report(
    *,
    tenant: str = "",
    bot: str = "",
    fields: int = 0,
    tag_sequences: int = 0,
    zwj_count: int = 0,
    controls: int = 0,
    hidden_bytes: int = 0,
) -> None:
    tenant_l, bot_l = _limit_tenant_bot_labels(tenant, bot)

    def _do() -> None:
        if fields:
            _emoji_fields_total.labels(tenant=tenant_l, bot=bot_l).inc(fields)
        if tag_sequences:
            _emoji_tag_sequences_total.labels(tenant=tenant_l, bot=bot_l).inc(
                tag_sequences
            )
        if zwj_count:
            _emoji_zwj_total.labels(tenant=tenant_l, bot=bot_l).inc(zwj_count)
        if controls:
            _emoji_controls_total.labels(tenant=tenant_l, bot=bot_l).inc(controls)
        if hidden_bytes:
            _emoji_hidden_text_bytes_total.labels(
                tenant=tenant_l, bot=bot_l
            ).inc(hidden_bytes)

    _best_effort("inc emoji zwj ingress metrics", _do)


_unicode_strings_sanitized_total = _get_or_create_counter(
    "guardrail_unicode_strings_sanitized_total",
    "Count of strings sanitized in ingress pipeline",
    ("tenant", "bot"),
)
_unicode_zero_width_removed_total = _get_or_create_counter(
    "guardrail_unicode_zero_width_removed_total",
    "Total zero-width/formatting codepoints removed at ingress",
    ("tenant", "bot"),
)
_unicode_bidi_controls_removed_total = _get_or_create_counter(
    "guardrail_unicode_bidi_controls_removed_total",
    "Total bidi control codepoints removed at ingress",
    ("tenant", "bot"),
)
_unicode_confusables_mapped_total = _get_or_create_counter(
    "guardrail_unicode_confusables_mapped_total",
    "Total basic confusable characters mapped to ASCII at ingress",
    ("tenant", "bot"),
)
_unicode_mixed_script_inputs_total = _get_or_create_counter(
    "guardrail_unicode_mixed_script_inputs_total",
    "Number of payloads exhibiting mixed Latin/Cyrillic/Greek scripts",
    ("tenant", "bot"),
)


def unicode_ingress_report(
    *,
    tenant: str = "",
    bot: str = "",
    strings_seen: int = 0,
    zero_width_removed: int = 0,
    bidi_controls_removed: int = 0,
    confusables_mapped: int = 0,
    mixed_scripts: int = 0,
) -> None:
    tenant_l, bot_l = _limit_tenant_bot_labels(tenant, bot)

    def _do() -> None:
        if strings_seen:
            _unicode_strings_sanitized_total.labels(
                tenant=tenant_l, bot=bot_l
            ).inc(strings_seen)
        if zero_width_removed:
            _unicode_zero_width_removed_total.labels(
                tenant=tenant_l, bot=bot_l
            ).inc(zero_width_removed)
        if bidi_controls_removed:
            _unicode_bidi_controls_removed_total.labels(
                tenant=tenant_l, bot=bot_l
            ).inc(bidi_controls_removed)
        if confusables_mapped:
            _unicode_confusables_mapped_total.labels(
                tenant=tenant_l, bot=bot_l
            ).inc(confusables_mapped)
        if mixed_scripts:
            _unicode_mixed_script_inputs_total.labels(
                tenant=tenant_l, bot=bot_l
            ).inc(mixed_scripts)

    _best_effort("inc unicode ingress metrics", _do)


# --- Decode ingress metrics --------------------------------------------------


_decode_base64_total = _get_or_create_counter(
    "guardrail_decode_base64_total",
    "Count of strings decoded from base64 at ingress",
    ("tenant", "bot"),
)
_decode_hex_total = _get_or_create_counter(
    "guardrail_decode_hex_total",
    "Count of strings decoded from hex at ingress",
    ("tenant", "bot"),
)
_decode_url_total = _get_or_create_counter(
    "guardrail_decode_url_total",
    "Count of strings decoded from url-encoding at ingress",
    ("tenant", "bot"),
)


def decode_ingress_report(
    *,
    tenant: str = "",
    bot: str = "",
    decoded_base64: int = 0,
    decoded_hex: int = 0,
    decoded_url: int = 0,
) -> None:
    tenant_l, bot_l = _limit_tenant_bot_labels(tenant, bot)

    def _do() -> None:
        if decoded_base64:
            _decode_base64_total.labels(tenant=tenant_l, bot=bot_l).inc(decoded_base64)
        if decoded_hex:
            _decode_hex_total.labels(tenant=tenant_l, bot=bot_l).inc(decoded_hex)
        if decoded_url:
            _decode_url_total.labels(tenant=tenant_l, bot=bot_l).inc(decoded_url)

    _best_effort("inc decode ingress metrics", _do)


# --- Archive ingress metrics -------------------------------------------------

_arch_candidates_total = _get_or_create_counter(
    "guardrail_archive_candidates_total",
    "JSON (filename,base64) pairs considered for archive peeking",
    ("tenant", "bot"),
)
_arch_detected_total = _get_or_create_counter(
    "guardrail_archives_detected_total",
    "Valid archives detected and inspected",
    ("tenant", "bot"),
)
_arch_filenames_total = _get_or_create_counter(
    "guardrail_archive_filenames_total",
    "Total filenames listed from inspected archives",
    ("tenant", "bot"),
)
_arch_text_samples_total = _get_or_create_counter(
    "guardrail_archive_text_samples_total",
    "Total text samples extracted from inspected archives",
    ("tenant", "bot"),
)
_arch_nested_blocked_total = _get_or_create_counter(
    "guardrail_archive_nested_blocked_total",
    "Nested archives blocked by limits",
    ("tenant", "bot"),
)
_arch_errors_total = _get_or_create_counter(
    "guardrail_archive_errors_total",
    "Errors encountered while peeking archives",
    ("tenant", "bot"),
)


def archive_ingress_report(
    *,
    tenant: str = "",
    bot: str = "",
    candidates: int = 0,
    archives_detected: int = 0,
    filenames: int = 0,
    text_samples: int = 0,
    nested_blocked: int = 0,
    errors: int = 0,
) -> None:
    tenant_l, bot_l = _limit_tenant_bot_labels(tenant, bot)

    def _do() -> None:
        if candidates:
            _arch_candidates_total.labels(tenant=tenant_l, bot=bot_l).inc(
                candidates
            )
        if archives_detected:
            _arch_detected_total.labels(tenant=tenant_l, bot=bot_l).inc(
                archives_detected
            )
        if filenames:
            _arch_filenames_total.labels(tenant=tenant_l, bot=bot_l).inc(filenames)
        if text_samples:
            _arch_text_samples_total.labels(tenant=tenant_l, bot=bot_l).inc(
                text_samples
            )
        if nested_blocked:
            _arch_nested_blocked_total.labels(tenant=tenant_l, bot=bot_l).inc(
                nested_blocked
            )
        if errors:
            _arch_errors_total.labels(tenant=tenant_l, bot=bot_l).inc(errors)

    _best_effort("inc archive ingress metrics", _do)


# --- Markup ingress metrics --------------------------------------------------


_markup_fields_with_markup_total = _get_or_create_counter(
    "guardrail_markup_fields_with_markup_total",
    "JSON string fields that appeared to contain markup (HTML/SVG) at ingress",
    ("tenant", "bot"),
)
_markup_scripts_removed_total = _get_or_create_counter(
    "guardrail_markup_scripts_removed_total",
    "Count of script blocks removed during markup stripping",
    ("tenant", "bot"),
)
_markup_styles_removed_total = _get_or_create_counter(
    "guardrail_markup_styles_removed_total",
    "Count of style blocks removed during markup stripping",
    ("tenant", "bot"),
)
_markup_foreign_removed_total = _get_or_create_counter(
    "guardrail_markup_foreign_removed_total",
    "Count of foreignObject blocks removed during markup stripping",
    ("tenant", "bot"),
)
_markup_tags_removed_total = _get_or_create_counter(
    "guardrail_markup_tags_removed_total",
    "Increment when residual tags were stripped (coarse indicator)",
    ("tenant", "bot"),
)


def markup_ingress_report(
    *,
    tenant: str = "",
    bot: str = "",
    fields_with_markup: int = 0,
    scripts_removed: int = 0,
    styles_removed: int = 0,
    foreign_removed: int = 0,
    tags_removed: int = 0,
) -> None:
    tenant_l, bot_l = _limit_tenant_bot_labels(tenant, bot)

    def _do() -> None:
        if fields_with_markup:
            _markup_fields_with_markup_total.labels(
                tenant=tenant_l, bot=bot_l
            ).inc(fields_with_markup)
        if scripts_removed:
            _markup_scripts_removed_total.labels(
                tenant=tenant_l, bot=bot_l
            ).inc(scripts_removed)
        if styles_removed:
            _markup_styles_removed_total.labels(
                tenant=tenant_l, bot=bot_l
            ).inc(styles_removed)
        if foreign_removed:
            _markup_foreign_removed_total.labels(
                tenant=tenant_l, bot=bot_l
            ).inc(foreign_removed)
        if tags_removed:
            _markup_tags_removed_total.labels(
                tenant=tenant_l, bot=bot_l
            ).inc(tags_removed)

    _best_effort("inc markup ingress metrics", _do)


GUARDRAIL_RATELIMIT_REDIS_SCRIPT_RELOAD_TOTAL = _get_or_create_counter(
    "guardrail_ratelimit_redis_script_reload_total",
    "Count of Redis rate-limit Lua reloads triggered by NOSCRIPT.",
)


webhook_retry_total = _get_or_create_counter(
    "guardrail_webhook_retry_total",
    "Webhook retries by reason",
    labelnames=("reason",),
)


webhook_abort_total = _get_or_create_counter(
    "guardrail_webhook_abort_total",
    "Webhook aborts by reason",
    labelnames=("reason",),
)


webhook_dlq_retry_total = _get_or_create_counter(
    "guardrail_webhook_dlq_retry_total",
    "Manual requeue operations on the webhook DLQ",
)


webhook_dlq_purge_total = _get_or_create_counter(
    "guardrail_webhook_dlq_purge_total",
    "Manual purge operations on the webhook DLQ",
)


guardrail_scope_autoconstraint_total = _get_or_create_counter(
    "guardrail_scope_autoconstraint_total",
    "Autoconstraint requests by mode/result/multi/endpoint",
    labelnames=("mode", "result", "multi", "endpoint"),
)


retention_preview_total = _get_or_create_counter(
    "guardrail_retention_preview_total",
    "Retention preview operations executed by admins",
)


retention_deleted_total = _get_or_create_counter(
    "guardrail_retention_deleted_total",
    "Retention deletes executed by admins",
    labelnames=("kind",),
)

secrets_strict_toggle_total = _get_or_create_counter(
    "guardrail_secrets_strict_toggle_total",
    "Admin toggled stricter secrets pack",
    labelnames=("action",),
)

admin_audit_total = _get_or_create_counter(
    "guardrail_admin_audit_total",
    "Admin action audit events",
    labelnames=("action", "outcome"),
)


def inc_ratelimit_script_reload() -> None:
    _best_effort(
        "inc guardrail_ratelimit_redis_script_reload_total",
        lambda: GUARDRAIL_RATELIMIT_REDIS_SCRIPT_RELOAD_TOTAL.inc(),
    )


def inc_scope_autoconstraint(
    *, mode: str, result: str, multi: bool, endpoint: str
) -> None:
    """Increment the autoconstraint counter with guarded labels."""

    def _do() -> None:
        guardrail_scope_autoconstraint_total.labels(
            mode=mode or "unknown",
            result=result or "unknown",
            multi="true" if multi else "false",
            endpoint=endpoint or "unknown",
        ).inc()

    _best_effort("inc guardrail_scope_autoconstraint_total", _do)


def _get_or_create_histogram(
    name: str,
    doc: str,
    labelnames: Tuple[str, ...] = (),
    registry: Optional[CollectorRegistry] = None,
    buckets: Tuple[float, ...] = (),
) -> Histogram:
    reg = registry or REGISTRY
    try:
        names_map = getattr(reg, "_names_to_collectors", None)
        if isinstance(names_map, dict):
            existing = names_map.get(name)
            if isinstance(existing, Histogram):
                return existing
    except Exception as e:  # pragma: no cover
        _log.debug("reuse histogram %s failed: %s", name, e)

    try:
        return Histogram(
            name,
            doc,
            labelnames=labelnames,
            registry=reg,
            buckets=buckets or Histogram.DEFAULT_BUCKETS,
        )
    except ValueError:
        try:
            names_map = getattr(reg, "_names_to_collectors", None)
            if isinstance(names_map, dict):
                found = names_map.get(name)
                if isinstance(found, Histogram):
                    return found
        except Exception as e:  # pragma: no cover
            _log.debug("fallback histogram lookup %s failed: %s", name, e)
    return Histogram(name, doc, labelnames=labelnames)


def _get_or_create_gauge(
    name: str,
    doc: str,
    labelnames: Tuple[str, ...] = (),
    registry: Optional[CollectorRegistry] = None,
) -> Gauge:
    reg = registry or REGISTRY
    try:
        names_map = getattr(reg, "_names_to_collectors", None)
        if isinstance(names_map, dict):
            existing = names_map.get(name)
            if isinstance(existing, Gauge):
                return existing
    except Exception as e:  # pragma: no cover
        _log.debug("reuse gauge %s failed: %s", name, e)

    try:
        return Gauge(name, doc, labelnames=labelnames, registry=reg)
    except ValueError:
        try:
            names_map = getattr(reg, "_names_to_collectors", None)
            if isinstance(names_map, dict):
                found = names_map.get(name)
                if isinstance(found, Gauge):
                    return found
        except Exception as e:  # pragma: no cover
            _log.debug("fallback gauge lookup %s failed: %s", name, e)
        return Gauge(name, doc, labelnames=labelnames)


# --- Probing / leakage heuristics --------------------------------------------

_probe_rate_exceeded_total = _get_or_create_counter(
    "guardrail_probe_rate_exceeded_total",
    "Requests where the per-session rate window was exceeded",
    ("tenant", "bot"),
)
_probe_rate_hits = _get_or_create_gauge(
    "guardrail_probe_rate_hits",
    "Requests counted in the current rolling window (best-effort)",
    ("tenant", "bot"),
)
_probe_leakage_hits_total = _get_or_create_counter(
    "guardrail_probe_leakage_hits_total",
    "Count of leakage-hint matches observed in incoming JSON strings",
    ("tenant", "bot"),
)
_probe_similarity_hits_total = _get_or_create_counter(
    "guardrail_probe_similarity_hits_total",
    "Near-duplicate similarity hits across consecutive requests",
    ("tenant", "bot"),
)


def probing_ingress_report(
    *,
    tenant: str = "",
    bot: str = "",
    rate_exceeded: int = 0,
    rate_hits: int = 0,
    leakage_hits: int = 0,
    similarity_hits: int = 0,
) -> None:
    tenant_l, bot_l = _limit_tenant_bot_labels(tenant, bot)

    def _do() -> None:
        if rate_exceeded:
            _probe_rate_exceeded_total.labels(tenant=tenant_l, bot=bot_l).inc(
                rate_exceeded
            )
        _probe_rate_hits.labels(tenant=tenant_l, bot=bot_l).set(rate_hits)
        if leakage_hits:
            _probe_leakage_hits_total.labels(tenant=tenant_l, bot=bot_l).inc(
                leakage_hits
            )
        if similarity_hits:
            _probe_similarity_hits_total.labels(tenant=tenant_l, bot=bot_l).inc(
                similarity_hits
            )

    _best_effort("inc probing ingress metrics", _do)


# --- Ops/health gauges -------------------------------------------------------

readyz_ok = _get_or_create_gauge(
    "guardrail_readyz_ok",
    "Overall readiness computed by /readyz (1=ready, 0=not ready).",
)

readyz_redis_ok = _get_or_create_gauge(
    "guardrail_readyz_redis_ok",
    "Redis readiness computed by /readyz (1=all configured Redis consumers healthy, 0 otherwise).",
)

# --- DLQ depth ---------------------------------------------------------------

webhook_dlq_depth = _get_or_create_gauge(
    "guardrail_webhook_dlq_depth",
    "Number of items currently in the webhook DLQ.",
)


# --- Session risk metrics ----------------------------------------------------

_session_risk_score = _get_or_create_gauge(
    "guardrail_session_risk_score",
    "Current risk score for a session",
    ("tenant", "bot"),
)
_session_risk_delta_total = _get_or_create_counter(
    "guardrail_session_risk_delta_total",
    "Cumulative risk increments observed",
    ("tenant", "bot"),
)


def session_risk_report(
    *,
    tenant: str = "",
    bot: str = "",
    session: str = "",
    base: float = 0.0,
    delta: float = 0.0,
    score: float = 0.0,
) -> None:
    t, b = _limit_tenant_bot_labels(tenant, bot)
    if delta:
        _session_risk_delta_total.labels(tenant=t, bot=b).inc(delta)
    _session_risk_score.labels(tenant=t, bot=b).set(score)


# ---- Verifier provider metrics (existing set) --------------------------------


@dataclass(frozen=True)
class VerifierMetrics:
    sampled_total: Counter
    skipped_total: Counter
    timeout_total: Counter
    duration_seconds: Histogram  # labeled by provider
    circuit_open_total: Counter
    error_total: Counter
    circuit_state: Optional[Gauge]


def make_verifier_metrics(registry: CollectorRegistry) -> VerifierMetrics:
    sampled = _get_or_create_counter(
        "guardrail_verifier_sampled_total",
        "Count of requests for which the verifier was invoked (sampled).",
        labelnames=("provider",),
        registry=registry,
    )
    skipped = _get_or_create_counter(
        "guardrail_verifier_skipped_total",
        "Count of requests skipped by sampling gate (not verified).",
        labelnames=("provider",),
        registry=registry,
    )
    timeout = _get_or_create_counter(
        "guardrail_verifier_timeout_total",
        "Count of verifier calls that exceeded the latency budget.",
        labelnames=("provider",),
        registry=registry,
    )
    circuit_open = _get_or_create_counter(
        "guardrail_verifier_circuit_open_total",
        "Count of calls skipped because the circuit breaker was open.",
        labelnames=("provider",),
        registry=registry,
    )
    errors = _get_or_create_counter(
        "guardrail_verifier_provider_error_total",
        "Count of verifier provider exceptions (excluding timeouts).",
        labelnames=("provider",),
        registry=registry,
    )
    duration = _get_or_create_histogram(
        "guardrail_verifier_duration_seconds",
        "Time spent in provider evaluation (successful or timed out).",
        labelnames=("provider",),
        registry=registry,
        buckets=(
            0.001,
            0.005,
            0.01,
            0.025,
            0.05,
            0.1,
            0.25,
            0.5,
            1.0,
            2.5,
            5.0,
            10.0,
        ),
    )

    try:
        circuit_state = _get_or_create_gauge(
            "guardrail_verifier_circuit_state",
            "State of verifier circuit breaker (1=open, 0=closed).",
            labelnames=("provider",),
            registry=registry,
        )
    except Exception as e:  # pragma: no cover
        _log.debug("create guardrail_verifier_circuit_state failed: %s", e)
        circuit_state = None

    return VerifierMetrics(
        sampled_total=sampled,
        skipped_total=skipped,
        timeout_total=timeout,
        duration_seconds=duration,
        circuit_open_total=circuit_open,
        error_total=errors,
        circuit_state=circuit_state,
    )


# Singleton (safe due to get_or_create semantics)
VERIFIER_METRICS: VerifierMetrics = make_verifier_metrics(REGISTRY)


# ---- Clarify / egress counters (existing) ------------------------------------

GUARDRAIL_CLARIFY_TOTAL = _get_or_create_counter(
    "guardrail_clarify_total",
    "Total clarify-first decisions",
    ("phase",),
)

GUARDRAIL_EGRESS_REDACTIONS_TOTAL = _get_or_create_counter(
    "guardrail_egress_redactions_total",
    "Total egress redactions applied",
    ("tenant", "bot", "kind", "rule_id"),
)

GUARDRAIL_MITIGATION_OVERRIDE_TOTAL = _get_or_create_counter(
    "guardrail_mitigation_override_total",
    "Count of decisions where a tenant/bot mitigation override was applied.",
    ("mode",),
)

# Alias for newer code paths that expect an explicitly named counter.
mitigation_override_counter = GUARDRAIL_MITIGATION_OVERRIDE_TOTAL


def inc_clarify(phase: str = "ingress") -> None:
    GUARDRAIL_CLARIFY_TOTAL.labels(phase=phase).inc()


def inc_egress_redactions(
    tenant: str,
    bot: str,
    kind: str,
    n: int = 1,
    *,
    rule_id: str | None = None,
) -> None:
    if n > 0:
        tenant_l, bot_l = _limit_tenant_bot_labels(tenant, bot)
        def _do() -> None:
            GUARDRAIL_EGRESS_REDACTIONS_TOTAL.labels(
                tenant=tenant_l,
                bot=bot_l,
                kind=kind,
                rule_id=rule_id or "",
            ).inc(n)

        _best_effort("inc guardrail_egress_redactions_total", _do)


def inc_mitigation_override(mode: str) -> None:
    if mode in ("block", "clarify", "redact"):
        _best_effort(
            "inc guardrail_mitigation_override_total",
            lambda: GUARDRAIL_MITIGATION_OVERRIDE_TOTAL.labels(mode=mode).inc(),
        )


# ---- Verifier router rank metric (Hybrid-12) ---------------------------------

VERIFIER_ROUTER_RANK_TOTAL = _get_or_create_counter(
    "verifier_router_rank_total",
    "Count of provider rank computations by tenant and bot.",
    ("tenant", "bot"),
    registry=REGISTRY,
)


def inc_verifier_router_rank(tenant: str, bot: str) -> None:
    """
    Increment the rank counter with canonical label set. Registered on REGISTRY,
    which your /metrics route exports.
    """
    tenant_l, bot_l = _limit_tenant_bot_labels(tenant, bot)

    _best_effort(
        "inc verifier_router_rank_total",
        lambda: VERIFIER_ROUTER_RANK_TOTAL.labels(tenant=tenant_l, bot=bot_l).inc(),
    )


# ---- Webhooks: DLQ length gauge ---------------------------------------------

_webhook_dlq_length = _get_or_create_gauge(
    "guardrail_webhook_dlq_length",
    "Number of webhook events currently queued in the DLQ.",
)


def webhook_dlq_length_set(n: float) -> None:
    _best_effort(
        "set guardrail_webhook_dlq_length",
        lambda: _webhook_dlq_length.set(float(n)),
    )


def webhook_dlq_length_inc(delta: float = 1) -> None:
    _best_effort(
        "inc guardrail_webhook_dlq_length",
        lambda: _webhook_dlq_length.inc(float(delta)),
    )


def webhook_dlq_length_dec(delta: float = 1) -> None:
    def _do() -> None:
        current = webhook_dlq_length_get()
        _webhook_dlq_length.set(max(0.0, current - float(delta)))

    _best_effort("dec guardrail_webhook_dlq_length", _do)


def webhook_dlq_length_get() -> float:
    try:
        for metric in _webhook_dlq_length.collect():
            for sample in metric.samples:
                return float(sample.value)
    except Exception as e:  # pragma: no cover
        _log.debug("get guardrail_webhook_dlq_length failed: %s", e)
    return 0.0


# ---- Webhooks: delivery worker metrics --------------------------------------

_webhook_processed_total = _get_or_create_counter(
    "guardrail_webhook_deliveries_processed_total",
    "Count of webhook deliveries that succeeded with a 2xx response.",
)

_webhook_retried_total = _get_or_create_counter(
    "guardrail_webhook_deliveries_retried_total",
    "Count of webhook delivery attempts that will be retried.",
)

_webhook_failed_total = _get_or_create_counter(
    "guardrail_webhook_deliveries_failed_total",
    "Count of webhook deliveries that were dropped after exhausting retries.",
)

_webhook_pending_queue_length = _get_or_create_gauge(
    "guardrail_webhook_pending_queue_length",
    "Current number of webhook events waiting to be delivered.",
)


def webhook_processed_inc(n: float = 1) -> None:
    _best_effort(
        "inc guardrail_webhook_deliveries_processed_total",
        lambda: _webhook_processed_total.inc(float(n)),
    )


def webhook_retried_inc(n: float = 1) -> None:
    _best_effort(
        "inc guardrail_webhook_deliveries_retried_total",
        lambda: _webhook_retried_total.inc(float(n)),
    )


def webhook_failed_inc(n: float = 1) -> None:
    _best_effort(
        "inc guardrail_webhook_deliveries_failed_total",
        lambda: _webhook_failed_total.inc(float(n)),
    )


def webhook_pending_set(n: float) -> None:
    _best_effort(
        "set guardrail_webhook_pending_queue_length",
        lambda: _webhook_pending_queue_length.set(float(n)),
    )
