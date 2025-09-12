from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

from app.services.bindings.models import Binding


@dataclass(frozen=True)
class BindingIssue:
    kind: str          # "duplicate" | "incompatible" | "overlap" | "shadowed" | "invalid"
    severity: str      # "error" | "warning" | "info"
    message: str
    a: Optional[Binding] = None
    b: Optional[Binding] = None

    def brief(self) -> str:
        return f"{self.severity}/{self.kind}: {self.message}"


def _format_key(b: Binding) -> str:
    return f"({b.tenant_id},{b.bot_id})"


def validate_bindings(
    bindings: Sequence[Binding],
    *,
    require_policy_nonempty: bool = True,
) -> List[BindingIssue]:
    issues: List[BindingIssue] = []

    # Basic field validation
    for b in bindings:
        if require_policy_nonempty and not (b.policy_version and b.policy_version.strip()):
            issues.append(
                BindingIssue(
                    kind="invalid",
                    severity="error",
                    message=f"Empty policy_version for {_format_key(b)}",
                    a=b,
                )
            )

    # Pairwise checks
    n = len(bindings)
    for i in range(n):
        bi = bindings[i]
        for j in range(i + 1, n):
            bj = bindings[j]

            if bi.identical_target(bj):
                if bi.semantically_equal(bj):
                    # Same target + same outcome => duplicate definition
                    issues.append(
                        BindingIssue(
                            kind="duplicate",
                            severity="warning",
                            message=(
                                f"Duplicate binding at {_format_key(bi)}; "
                                f"consider removing one (priorities {bi.priority}/{bj.priority})."
                            ),
                            a=bi,
                            b=bj,
                        )
                    )
                else:
                    # Same target but different outcome => incompatible
                    issues.append(
                        BindingIssue(
                            kind="incompatible",
                            severity="error",
                            message=(
                                f"Conflicting binding definitions at {_format_key(bi)}: "
                                f"policy/model differ."
                            ),
                            a=bi,
                            b=bj,
                        )
                    )
                continue

            # Overlap via wildcard(s)
            if bi.overlaps(bj):
                if bi.priority == bj.priority:
                    issues.append(
                        BindingIssue(
                            kind="overlap",
                            severity="warning",
                            message=(
                                f"Overlapping bindings {_format_key(bi)} (p={bi.priority}) "
                                f"and {_format_key(bj)} (p={bj.priority}) with equal priority; "
                                "resolution is ambiguous."
                            ),
                            a=bi,
                            b=bj,
                        )
                    )
                else:
                    # Not an error: higher priority wins; inform that the lower is shadowed
                    higher, lower = (bi, bj) if bi.priority > bj.priority else (bj, bi)
                    issues.append(
                        BindingIssue(
                            kind="shadowed",
                            severity="info",
                            message=(
                                f"Binding {_format_key(lower)} (p={lower.priority}) is "
                                f"shadowed by {_format_key(higher)} (p={higher.priority})."
                            ),
                            a=lower,
                            b=higher,
                        )
                    )

    return issues


def choose_binding_for(
    bindings: Sequence[Binding], tenant_id: str, bot_id: str
) -> Tuple[Optional[Binding], List[Binding]]:
    """
    Return the selected binding for (tenant_id, bot_id) using priority tie-break,
    plus the list of candidates that matched. Useful for dry-runs in admin UIs.
    """
    candidates: List[Binding] = []
    for b in bindings:
        if (b.tenant_id in (tenant_id, "*")) and (b.bot_id in (bot_id, "*")):
            candidates.append(b)
    if not candidates:
        return None, []

    # Highest priority wins; stable tiebreaker by specificity then insertion order
    def score(b: Binding) -> Tuple[int, int, int]:
        specificity = int(b.tenant_id != "*") + int(b.bot_id != "*")
        return (b.priority, specificity, 0)

    selected = sorted(candidates, key=score, reverse=True)[0]
    return selected, candidates

