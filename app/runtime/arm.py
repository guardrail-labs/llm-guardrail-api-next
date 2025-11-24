"""Runtime helpers for guardrail arm health and mode management."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Literal, Tuple, cast

from app import settings as settings_module
from app.telemetry import metrics


class ArmMode(str, Enum):
    """Runtime mode for guardrail arm coordination."""

    NORMAL = "normal"
    EGRESS_ONLY = "egress_only"

    @property
    def header_value(self) -> str:
        """Return the HTTP header-friendly representation of the mode."""

        return self.value.replace("_", "-")


@dataclass(frozen=True)
class ArmStatus:
    """Simple health status for an arm."""

    state: str
    reason: str

    def to_dict(self) -> Dict[str, str]:
        return {"state": self.state, "reason": self.reason}


ArmProbeState = Literal["up", "degraded", "down"]


class IngressHealthProbe:
    """Evaluate whether ingress is degraded based on simple signals."""

    def __init__(self, *, lag_threshold_ms: int) -> None:
        self._lag_threshold_ms = lag_threshold_ms
        self._queue_lag_ms: float | None = None
        self._forced_state: ArmProbeState | None = None
        self._forced_reason: str = ""
        self._lock = threading.RLock()

    def reset(self) -> None:
        with self._lock:
            self._queue_lag_ms = None
            self._forced_state = None
            self._forced_reason = ""

    def force_state(self, state: str | None, reason: str | None = None) -> None:
        """Force the probe into a specific state (tests/instrumentation)."""

        normalized: str | None
        if state is None:
            normalized = None
        else:
            normalized = state.strip().lower()
            if normalized not in {"up", "degraded", "down"}:
                raise ValueError(f"invalid forced state: {state!r}")
        with self._lock:
            self._forced_state = cast(ArmProbeState | None, normalized)
            self._forced_reason = (reason or "").strip()

    def observe_queue_lag(self, lag_ms: float | int | None) -> None:
        with self._lock:
            if lag_ms is None:
                self._queue_lag_ms = None
            else:
                self._queue_lag_ms = float(lag_ms)

    def status(self) -> Tuple[ArmProbeState, str]:
        """Return the ingress state and optional reason."""

        with self._lock:
            forced = self._forced_state
            reason = self._forced_reason
            if forced == "down":
                return "down", reason or "ingress arm forced down"
            if forced == "degraded":
                return "degraded", reason or "ingress arm forced degraded"
            if forced == "up":
                return "up", ""

            lag_ms = self._queue_lag_ms
            if lag_ms is not None and lag_ms > self._lag_threshold_ms:
                rounded = int(lag_ms)
                return (
                    "degraded",
                    f"ingress queue lag {rounded}ms > {self._lag_threshold_ms}ms",
                )
        return "up", ""


class ArmRuntime:
    """Coordinate arm health, mode, and observability."""

    def __init__(self) -> None:
        self._settings = settings_module
        self._lock = threading.RLock()
        self._probe = IngressHealthProbe(
            lag_threshold_ms=getattr(self._settings, "INGRESS_DEGRADED_LAG_MS", 2000)
        )
        self._mode = ArmMode.NORMAL
        self._ingress_status = ArmStatus("up", "healthy")
        self._egress_status = ArmStatus(
            "up" if self.egress_enabled else "down",
            "enabled" if self.egress_enabled else "egress arm disabled",
        )
        self._last_degradation_reason = ""
        self._update_metrics_locked()

    @property
    def ingress_enabled(self) -> bool:
        return bool(getattr(self._settings, "ARM_INGRESS_ENABLED", True))

    @property
    def egress_enabled(self) -> bool:
        return bool(getattr(self._settings, "ARM_EGRESS_ENABLED", True))

    @property
    def mode(self) -> ArmMode:
        return self._mode

    @property
    def ingress_degradation_reason(self) -> str:
        return self._last_degradation_reason

    def reset_for_tests(self) -> None:
        with self._lock:
            self._probe.reset()
            self._mode = ArmMode.NORMAL
            self._last_degradation_reason = ""
            self._ingress_status = ArmStatus("up", "healthy")
            self._egress_status = ArmStatus(
                "up" if self.egress_enabled else "down",
                "enabled" if self.egress_enabled else "egress arm disabled",
            )
            self._update_metrics_locked()

    def force_ingress_degraded(self, reason: str | None = None) -> None:
        self._probe.force_state("degraded", reason)

    def force_ingress_down(self, reason: str | None = None) -> None:
        self._probe.force_state("down", reason)

    def clear_forced_ingress_state(self) -> None:
        self._probe.force_state(None)

    def record_ingress_queue_lag(self, lag_ms: float | int | None) -> None:
        self._probe.observe_queue_lag(lag_ms)

    def _evaluate_ingress_locked(self) -> Tuple[bool, str, ArmStatus]:
        if not self.ingress_enabled:
            return True, "ingress arm disabled", ArmStatus("down", "ingress arm disabled")

        state, reason = self._probe.status()
        if state == "down":
            final_reason = reason or "ingress down"
            return True, final_reason, ArmStatus("down", final_reason)
        if state == "degraded":
            final_reason = reason or "ingress degraded"
            return True, final_reason, ArmStatus("degraded", final_reason)
        return False, "", ArmStatus("up", "healthy")

    def is_ingress_degraded(self) -> bool:
        with self._lock:
            degraded, reason, status = self._evaluate_ingress_locked()
            self._ingress_status = status
            self._last_degradation_reason = reason
            self._update_metrics_locked()
            return degraded

    def evaluate_mode(self) -> ArmMode:
        with self._lock:
            degraded, reason, ingress_status = self._evaluate_ingress_locked()
            self._ingress_status = ingress_status
            self._last_degradation_reason = reason

            if not self.egress_enabled:
                self._egress_status = ArmStatus("down", "egress arm disabled")
            else:
                self._egress_status = ArmStatus("up", "enabled")

            target = self._mode
            if degraded and getattr(self._settings, "EGRESS_ONLY_ON_INGRESS_DEGRADED", True):
                target = ArmMode.EGRESS_ONLY if self.egress_enabled else ArmMode.NORMAL
            elif not degraded:
                target = ArmMode.NORMAL

            if target != self._mode:
                metrics.guardrail_arm_transitions_total.labels(self._mode.value, target.value).inc()
                self._mode = target

            self._update_metrics_locked()
            return self._mode

    def snapshot(self) -> Dict[str, Any]:
        mode = self.evaluate_mode()
        with self._lock:
            return {
                "mode": mode.value,
                "mode_header": mode.header_value,
                "ingress": self._ingress_status.to_dict(),
                "egress": self._egress_status.to_dict(),
                "ingress_degradation_reason": self._last_degradation_reason,
            }

    def _update_metrics_locked(self) -> None:
        ingress_state = self._ingress_status.state
        egress_state = self._egress_status.state
        for state in ("up", "degraded", "down"):
            metrics.guardrail_arm_status.labels("ingress", state).set(
                1.0 if ingress_state == state else 0.0
            )
            metrics.guardrail_arm_status.labels("egress", state).set(
                1.0 if egress_state == state else 0.0
            )
        for mode in ArmMode:
            metrics.guardrail_arm_mode.labels(mode.value).set(1.0 if self._mode == mode else 0.0)


_runtime: ArmRuntime | None = None


def get_arm_runtime() -> ArmRuntime:
    global _runtime
    if _runtime is None:
        _runtime = ArmRuntime()
    return _runtime


def is_ingress_degraded() -> bool:
    return get_arm_runtime().is_ingress_degraded()


def current_guardrail_mode() -> str:
    """Return the current guardrail mode as a response-safe string."""

    try:
        mode = get_arm_runtime().evaluate_mode()
    except Exception:
        return ArmMode.NORMAL.header_value

    if isinstance(mode, ArmMode):
        return mode.header_value

    header_value = getattr(mode, "header_value", None)
    if isinstance(header_value, str):
        return header_value

    value = getattr(mode, "value", None)
    if isinstance(value, str):
        return value.replace("_", "-")

    if isinstance(mode, str):
        return mode.replace("_", "-")

    return ArmMode.NORMAL.header_value


__all__ = [
    "ArmMode",
    "ArmRuntime",
    "ArmStatus",
    "current_guardrail_mode",
    "get_arm_runtime",
    "is_ingress_degraded",
]
