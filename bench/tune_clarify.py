from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional


def recommend_thresholds(results_json: str) -> Dict[str, Any]:
    """Naive tuner: increase threshold if clarify rate is above the target."""
    data = json.loads(Path(results_json).read_text(encoding="utf-8"))
    summary = data.get("summary", {})
    decisions = summary.get("decisions", {})
    total = int(summary.get("count", 0))
    total = max(total, 1)
    clarify = int(decisions.get("clarify", 0)) + int(decisions.get("block_input", 0))
    rate = clarify / total
    target = float(summary.get("clarify_target", 0.15))
    recommendation: Dict[str, Any] = {
        "observed_rate": rate,
        "target_rate": target,
    }
    if rate > target:
        recommendation["max_confusables_ratio_delta"] = 0.01
    else:
        recommendation["max_confusables_ratio_delta"] = 0.0
    return recommendation


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", required=True)
    args = parser.parse_args(argv)
    rec = recommend_thresholds(args.results)
    print(json.dumps(rec, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
