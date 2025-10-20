from __future__ import annotations

import json
from pathlib import Path
from typing import List


def main() -> int:
    roots: List[Path] = [
        Path("ops/grafana/dashboards"),
        Path("ops/grafana/alerts"),
    ]
    for root in roots:
        for path in root.glob("*.json"):
            try:
                json.loads(path.read_text(encoding="utf-8"))
            except Exception as exc:  # noqa: BLE001
                print(f"Invalid JSON: {path}: {exc}")
                return 1
    print("Grafana JSON OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
