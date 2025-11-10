from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict

import requests  # type: ignore


def _build_params(args: argparse.Namespace) -> Dict[str, str]:
    params: Dict[str, str] = {"tenant": args.tenant}
    if args.incident_id:
        params["incident_id"] = args.incident_id
    if args.start:
        params["start"] = args.start
    if args.end:
        params["end"] = args.end
    return params


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--incident-id")
    parser.add_argument("--start")
    parser.add_argument("--end")
    parser.add_argument("--outdir", default="audit_exports")
    args = parser.parse_args()

    params = _build_params(args)
    base = args.base_url.rstrip("/")

    json_response = requests.get(f"{base}/admin/audit/export", params={**params, "fmt": "json"})
    json_response.raise_for_status()
    bundle = json_response.json()

    csv_response = requests.get(f"{base}/admin/audit/export", params={**params, "fmt": "csv"})
    csv_response.raise_for_status()
    csv_text = csv_response.text

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    json_path = outdir / "bundle.json"
    csv_path = outdir / "bundle.csv"
    json_path.write_text(json.dumps(bundle, indent=2), encoding="utf-8")
    csv_path.write_text(csv_text, encoding="utf-8")
    print(f"Wrote {json_path} and {csv_path}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
