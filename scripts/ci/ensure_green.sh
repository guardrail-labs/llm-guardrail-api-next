#!/usr/bin/env bash
set -euo pipefail
mkdir -p reports
python -m ruff format --check .
python -m ruff check .
python -m mypy . --strict
pytest -q --maxfail=1 --disable-warnings \
  --junitxml=reports/junit.xml --cov=app --cov-report=xml
