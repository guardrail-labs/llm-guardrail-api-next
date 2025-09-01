from __future__ import annotations

import re
import threading
from typing import Dict, Tuple, List

# ----------------------------
# Decision-family counters (global)
# ----------------------------
_FAMILY_LOCK = threading.RLock()
_FAMILY: Dict[str, float] = {
    "allow": 0.0,
    "block": 0.0,
    "sanitize": 0.0,
    "verify": 0.0,
}


def inc_decision_family(name: str, by: float = 1.0) -> None:
    key = (name or "").lower().strip()
    if key not in _FAMILY:
        return
    with _FAMILY_LOCK:
        _FAMILY[key] += float(by)


def get_decisions_family_total(name: str) -> float:
    key = (name or "").lower().strip()
    if key not in _FAMILY:
        return 0.0
    with _FAMILY_LOCK:
        return float(_FAMILY[key])


def get_all_family_totals() -> Dict[str, float]:
    with _FAMILY_LOCK:
        return {k: float(v) for k, v in _FAMILY.items()}


# ----------------------------
# Rate-limited counter (global)
# ----------------------------
_RATE_LIMIT_LOCK = threading.RLock()
_RATE_LIMITED_TOTAL: float = 0.0


def inc_rate_limited(by: float = 1.0) -> None:
    global _RATE_LIMITED_TOTAL
    with _RATE_LIMIT_LOCK:
        _RATE_LIMITED_TOTAL += float(by)


def get_rate_limited_total() -> float:
    with _RATE_LIMIT_LOCK:
        return float(_RATE_LIMITED_TOTAL)


# ----------------------------
# Tenant/Bot breakdown (capped cardinality)
# ----------------------------

# Hard caps to prevent label explosion
_MAX_TENANTS = 20
_MAX_BOTS_PER_TENANT = 20
_OTHER = "other"

_LABEL_SAFE = re.compile(r"[^a-zA-Z0-9._-]")


def _sanitize_label(val: str) -> str:
    v = (val or "").strip()
    if not v:
        return _OTHER
    # limit length & charset
    v = _LABEL_SAFE.sub("_", v)[:64]
    return v.lower() or _OTHER


_T_LOCK = threading.RLock()
# tenant -> family -> count
_TENANT_FAMILY: Dict[str, Dict[str, float]] = {}
# (tenant -> (bot -> (family -> count)))
_BOT_FAMILY: Dict[str, Dict[str, Dict[str, float]]] = {}


def _ensure_tenant_bucket(tenant: str) -> str:
    t = _sanitize_label(tenant)
    with _T_LOCK:
        if t in _TENANT_FAMILY:
            return t
        if len(_TENANT_FAMILY) < _MAX_TENANTS:
            _TENANT_FAMILY[t] = {"allow": 0.0, "block": 0.0, "sanitize": 0.0, "verify": 0.0}
            if t not in _BOT_FAMILY:
                _BOT_FAMILY[t] = {}
            return t
        # overflow
        if _OTHER not in _TENANT_FAMILY:
            _TENANT_FAMILY[_OTHER] = {"allow": 0.0, "block": 0.0, "sanitize": 0.0, "verify": 0.0}
            if _OTHER not in _BOT_FAMILY:
                _BOT_FAMILY[_OTHER] = {}
        return _OTHER


def _ensure_bot_bucket(tenant_key: str, bot: str) -> str:
    b = _sanitize_label(bot)
    with _T_LOCK:
        bots = _BOT_FAMILY.setdefault(tenant_key, {})
        if b in bots:
            return b
        if len(bots) < _MAX_BOTS_PER_TENANT:
            bots[b] = {"allow": 0.0, "block": 0.0, "sanitize": 0.0, "verify": 0.0}
            return b
        if _OTHER not in bots:
            bots[_OTHER] = {"allow": 0.0, "block": 0.0, "sanitize": 0.0, "verify": 0.0}
        return _OTHER


def inc_decision_family_tenant_bot(tenant: str, bot: str, family: str, by: float = 1.0) -> None:
    fam = (family or "").lower().strip()
    if fam not in ("allow", "block", "sanitize", "verify"):
        return
    # Always increment global
    inc_decision_family(fam, by)

    with _T_LOCK:
        t_key = _ensure_tenant_bucket(tenant)
        _TENANT_FAMILY[t_key][fam] += float(by)
        b_key = _ensure_bot_bucket(t_key, bot)
        _BOT_FAMILY[t_key][b_key][fam] += float(by)


def get_family_tenant_totals() -> Dict[Tuple[str, str], float]:
    out: Dict[Tuple[str, str], float] = {}
    with _T_LOCK:
        for t, fams in _TENANT_FAMILY.items():
            for fam, v in fams.items():
                out[(t, fam)] = float(v)
    return out


def get_family_bot_totals() -> Dict[Tuple[str, str, str], float]:
    out: Dict[Tuple[str, str, str], float] = {}
    with _T_LOCK:
        for t, bots in _BOT_FAMILY.items():
            for b, fams in bots.items():
                for fam, v in fams.items():
                    out[(t, b, fam)] = float(v)
    return out


def export_family_breakdown_lines() -> List[str]:
    """
    Returns Prometheus text lines for:
      - guardrail_decisions_family_tenant_total{tenant, family}
      - guardrail_decisions_family_bot_total{tenant, bot, family}
    """
    lines: List[str] = []
    # tenant level
    t_totals = get_family_tenant_totals()
    if t_totals:
        lines.append("# HELP guardrail_decisions_family_tenant_total Decisions by family per tenant.")
        lines.append("# TYPE guardrail_decisions_family_tenant_total counter")
        for (tenant, fam), v in sorted(t_totals.items()):
            lines.append(f'guardrail_decisions_family_tenant_total{{tenant="{tenant}",family="{fam}"}} {v}')
    # bot level
    b_totals = get_family_bot_totals()
    if b_totals:
        lines.append("# HELP guardrail_decisions_family_bot_total Decisions by family per bot.")
        lines.append("# TYPE guardrail_decisions_family_bot_total counter")
        for (tenant, bot, fam), v in sorted(b_totals.items()):
            lines.append(f'guardrail_decisions_family_bot_total{{tenant="{tenant}",bot="{bot}",family="{fam}"}} {v}')
    return lines

