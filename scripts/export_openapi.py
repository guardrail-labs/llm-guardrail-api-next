"""Export OpenAPI schema to openapi.json in repo root.

Run with:  python -m scripts.export_openapi
"""
from __future__ import annotations

import json
from pathlib import Path

from app.main import app


def main() -> None:
    schema = app.openapi()
    out = Path("openapi.json").resolve()
    out.write_text(json.dumps(schema, indent=2), encoding="utf-8")
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
