#!/usr/bin/env bash
set -euo pipefail

python -m ruff format --check .
python -m ruff check .
python -m mypy . --strict
mkdir -p reports
pytest -q --maxfail=1 --disable-warnings \
  --junitxml=reports/junit.xml \
  --cov=app --cov-report=xml
