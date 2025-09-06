from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Dict, TypedDict


class QuotaDecision(TypedDict):
    allowed: bool
    reason: str            # "ok" | "day" | "month"
    retry_after_s: int
    day_remaining: int
    month_remaining: int


class QuotaStatus(TypedDict):
    day_count: int
    month_count: int
    day_remaining: int
    month_remaining: int
    day_window_start: int
    month_window_start: int
    reset_day_s: int
    reset_month_s: int
    reset_earliest_s: int


@dataclass
class _Counter:
    window_start: int
    count: int


class FixedWindowQuotaStore:
    """
    Fixed UTC windows for daily and monthly request counts per key.

    - Windows reset on UTC day/month boundaries.
    - Counts requests (not tokens).
    - Thread-safe-by-design via GIL for dict ops (sufficient for tests).
    """

    def __init__(
        self,
        per_day: int,
        per_month: int,
        *,
        now_fn: Callable[[], float] | None = None,
    ) -> None:
        self.per_day = max(0, per_day)
        self.per_month = max(0, per_month)
        self._now = now_fn or time.time
        self._day: Dict[str, _Counter] = {}
        self._mon: Dict[str, _Counter] = {}

    @staticmethod
    def _utc_day_start(ts: int) -> int:
        # 00:00:00 UTC for the given timestamp day
        return ts - (ts % 86400)

    @staticmethod
    def _utc_month_start(ts: int) -> int:
        import datetime as _dt
        d = _dt.datetime.utcfromtimestamp(ts)
        m0 = _dt.datetime(d.year, d.month, 1, tzinfo=_dt.timezone.utc)
        return int(m0.timestamp())

    def check_and_inc(self, key: str) -> QuotaDecision:
        now = int(self._now())
        d0 = self._utc_day_start(now)
        m0 = self._utc_month_start(now)

        dctr = self._day.get(key)
        if not dctr or dctr.window_start != d0:
            dctr = _Counter(window_start=d0, count=0)
            self._day[key] = dctr

        mctr = self._mon.get(key)
        if not mctr or mctr.window_start != m0:
            mctr = _Counter(window_start=m0, count=0)
            self._mon[key] = mctr

        day_remaining = max(0, self.per_day - dctr.count)
        month_remaining = max(0, self.per_month - mctr.count)

        if day_remaining > 0 and month_remaining > 0:
            dctr.count += 1
            mctr.count += 1
            return QuotaDecision(
                allowed=True,
                reason="ok",
                retry_after_s=0,
                day_remaining=max(0, self.per_day - dctr.count),
                month_remaining=max(0, self.per_month - mctr.count),
            )

        # compute resets
        import datetime as _dt
        day_reset = (d0 + 86400) - now
        d = _dt.datetime.utcfromtimestamp(now)
        next_month_year = d.year + (1 if d.month == 12 else 0)
        next_month_month = 1 if d.month == 12 else d.month + 1
        next_m0 = _dt.datetime(next_month_year, next_month_month, 1, tzinfo=_dt.timezone.utc)
        mon_reset = int(next_m0.timestamp()) - now

        if day_remaining == 0 and month_remaining == 0:
            reason = "day" if day_reset <= mon_reset else "month"
            retry = min(day_reset, mon_reset)
        elif day_remaining == 0:
            reason = "day"
            retry = day_reset
        else:
            reason = "month"
            retry = mon_reset

        return QuotaDecision(
            allowed=False,
            reason=reason,
            retry_after_s=max(1, int(retry)),
            day_remaining=day_remaining,
            month_remaining=month_remaining,
        )

    # ---------- NEW: non-mutating status peek ----------
    def peek(self, key: str) -> QuotaStatus:
        now = int(self._now())
        d0 = self._utc_day_start(now)
        m0 = self._utc_month_start(now)

        dctr = self._day.get(key)
        d_count = dctr.count if dctr and dctr.window_start == d0 else 0

        mctr = self._mon.get(key)
        m_count = mctr.count if mctr and mctr.window_start == m0 else 0

        day_remaining = max(0, self.per_day - d_count)
        month_remaining = max(0, self.per_month - m_count)

        # Resets
        day_reset_s = (d0 + 86400) - now

        import datetime as _dt

        d = _dt.datetime.utcfromtimestamp(now)
        next_month_year = d.year + (1 if d.month == 12 else 0)
        next_month_month = 1 if d.month == 12 else d.month + 1
        next_m0 = _dt.datetime(next_month_year, next_month_month, 1, tzinfo=_dt.timezone.utc)
        mon_reset_s = int(next_m0.timestamp()) - now

        return QuotaStatus(
            day_count=int(d_count),
            month_count=int(m_count),
            day_remaining=int(day_remaining),
            month_remaining=int(month_remaining),
            day_window_start=int(d0),
            month_window_start=int(m0),
            reset_day_s=max(1, int(day_reset_s)),
            reset_month_s=max(1, int(mon_reset_s)),
            reset_earliest_s=max(1, int(min(day_reset_s, mon_reset_s))),
        )

    # ---------- NEW: reset counters for a key ----------
    def reset_key(self, key: str, *, which: str = "both") -> None:
        w = (which or "both").lower()
        if w in ("day", "both"):
            if key in self._day:
                self._day.pop(key, None)
        if w in ("month", "both"):
            if key in self._mon:
                self._mon.pop(key, None)

