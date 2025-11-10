#!/usr/bin/env bash
set -euo pipefail
python -m mypy --config-file mypy.ini --strict
